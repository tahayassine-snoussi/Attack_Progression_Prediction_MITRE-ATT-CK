#!/usr/bin/env python3
"""
Hybrid Attack Chain Prediction Pipeline (v3)
=============================================
Fixes from v2:
  - Reverted GRU to unidirectional (bidirectional overfit)
  - Removed aggressive class weights (destroyed validation loss)
  - Fixed tactic penalty: only blocks backward moves, not same-tactic
  - Ensemble preserved but now uses the working GRU
"""

import json
import random
import argparse
from collections import defaultdict, Counter

import numpy as np

SEED = 42
random.seed(SEED)
np.random.seed(SEED)

ALPHA = 0.1
EMBED_DIM = 64
HIDDEN_DIM = 128
DROPOUT = 0.3
BATCH_SIZE = 32
LEARNING_RATE = 1e-3
MAX_EPOCHS = 100
PATIENCE = 10
MAX_SEQ_LEN = 20
FUSION_ALPHA = 0.6
FUSION_BETA = 0.4

TID_TO_TACTIC = {
    'T1590.001': 'Reconnaissance', 'T1016': 'Discovery', 'T1190': 'Initial Access',
    'T1133': 'Initial Access', 'T1078': 'Initial Access', 'T1505.003': 'Persistence',
    'T1105': 'Command and Control', 'T1203': 'Execution', 'T1204': 'Execution',
    'T1021.001': 'Lateral Movement', 'T1021.002': 'Lateral Movement',
    'T1021.004': 'Lateral Movement', 'T1046': 'Reconnaissance',
    'T1595.001': 'Reconnaissance', 'T1595.002': 'Reconnaissance',
    'T1590.002': 'Reconnaissance', 'T1592': 'Reconnaissance', 'T1083': 'Discovery',
    'T1018': 'Discovery', 'T1049': 'Discovery', 'T1110': 'Credential Access',
    'T1110.001': 'Credential Access', 'T1110.003': 'Credential Access',
    'T1210': 'Lateral Movement', 'T1071.001': 'Command and Control',
    'T1071.004': 'Command and Control', 'T1572': 'Command and Control',
    'T1095': 'Command and Control', 'T1041': 'Exfiltration',
    'T1048.003': 'Exfiltration', 'T1567': 'Exfiltration', 'T1048': 'Exfiltration',
    'T1039': 'Collection', 'T1213': 'Collection', 'T1071.002': 'Command and Control',
    'T1496': 'Impact', 'T1497': 'Defense Evasion', 'T1568.002': 'Command and Control',
    'T1189': 'Initial Access', 'T1059.001': 'Execution', 'T1059': 'Execution',
    'T1003.001': 'Credential Access', 'T1003.008': 'Credential Access',
    'T1027': 'Defense Evasion', 'T1204.002': 'Execution', 'T1547.001': 'Persistence',
    'T1053.005': 'Persistence', 'T1543.003': 'Persistence', 'T1087.002': 'Discovery',
    'T1069.002': 'Discovery', 'T1059.004': 'Execution', 'T1548.003': 'Privilege Escalation',
    'T1033': 'Discovery'
}

TACTIC_ORDER = {
    'Reconnaissance': 1, 'Resource Development': 2, 'Initial Access': 3,
    'Execution': 4, 'Persistence': 5, 'Privilege Escalation': 6,
    'Defense Evasion': 7, 'Credential Access': 8, 'Discovery': 9,
    'Lateral Movement': 10, 'Collection': 11, 'Command and Control': 12,
    'Exfiltration': 13, 'Impact': 14
}


def load_sequences(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def build_vocab(sequences, supported_techniques=None):
    tids = set()
    for seq in sequences:
        for t in seq["sequence"]:
            if supported_techniques is None or t in supported_techniques:
                tids.add(t)
    vocab = ["<PAD>", "<UNK>"] + sorted(tids)
    tid2idx = {t: i for i, t in enumerate(vocab)}
    idx2tid = {i: t for t, i in tid2idx.items()}
    return vocab, tid2idx, idx2tid


def campaign_level_split(sequences, train_ratio=0.70, val_ratio=0.15):
    campaigns = list(sequences)
    random.shuffle(campaigns)
    n = len(campaigns)
    n_train = int(n * train_ratio)
    n_val = int(n * val_ratio)
    return campaigns[:n_train], campaigns[n_train:n_train + n_val], campaigns[n_train + n_val:]


def sequences_to_examples(seq_list):
    examples = []
    for seq in seq_list:
        s = seq["sequence"]
        for i in range(1, len(s)):
            examples.append({"campaign": seq["campaign"], "prefix": s[:i], "target": s[i]})
    return examples


class MarkovModel:
    def __init__(self, order=1, alpha=ALPHA):
        self.order = order
        self.alpha = alpha
        self.counts = defaultdict(Counter)
        self.totals = defaultdict(int)

    def fit(self, examples):
        for ex in examples:
            prefix = ex["prefix"]
            target = ex["target"]
            history = tuple(prefix[-self.order:]) if len(prefix) >= self.order else tuple(prefix)
            self.counts[history][target] += 1
            self.totals[history] += 1

    def predict(self, history, vocab_tid2idx, top_k=5):
        scores = {}
        for o in range(self.order, 0, -1):
            h = tuple(history[-o:]) if len(history) >= o else tuple(history)
            total = self.totals[h]
            if total == 0:
                continue
            for tid in vocab_tid2idx:
                if tid in ("<PAD>", "<UNK>"):
                    continue
                count = self.counts[h].get(tid, 0)
                prob = (count + self.alpha) / (total + self.alpha * (len(vocab_tid2idx) - 2))
                if tid not in scores:
                    scores[tid] = prob
            if scores:
                break
        if not scores:
            for tid in vocab_tid2idx:
                if tid not in ("<PAD>", "<UNK>"):
                    scores[tid] = 1.0 / (len(vocab_tid2idx) - 2)
        return sorted(scores.items(), key=lambda x: x[1], reverse=True)[:top_k]


try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import Dataset, DataLoader
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    print("[WARNING] PyTorch not installed. GRU model will be skipped.")


class SequenceDataset(Dataset):
    def __init__(self, examples, tid2idx, max_len=MAX_SEQ_LEN):
        self.examples = examples
        self.tid2idx = tid2idx
        self.max_len = max_len

    def __len__(self):
        return len(self.examples)

    def __getitem__(self, idx):
        ex = self.examples[idx]
        prefix = ex["prefix"][-self.max_len:]
        x = [self.tid2idx.get(t, self.tid2idx["<UNK>"]) for t in prefix]
        if len(x) < self.max_len:
            x = [self.tid2idx["<PAD>"]] * (self.max_len - len(x)) + x
        y = self.tid2idx.get(ex["target"], self.tid2idx["<UNK>"])
        return torch.tensor(x, dtype=torch.long), torch.tensor(y, dtype=torch.long)


class GRUPredictor(nn.Module):
    def __init__(self, vocab_size, embed_dim=EMBED_DIM, hidden_dim=HIDDEN_DIM, dropout=DROPOUT):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.gru = nn.GRU(embed_dim, hidden_dim, batch_first=True, bidirectional=False)
        self.dropout = nn.Dropout(dropout)
        self.fc = nn.Linear(hidden_dim, vocab_size)

    def forward(self, x):
        emb = self.embedding(x)
        out, hidden = self.gru(emb)
        logits = self.fc(self.dropout(hidden.squeeze(0)))
        return logits


def train_gru(train_loader, val_loader, vocab_size, device="cpu"):
    model = GRUPredictor(vocab_size).to(device)
    criterion = nn.CrossEntropyLoss(ignore_index=0)
    optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE)
    best_val_loss = float("inf")
    patience_counter = 0

    for epoch in range(MAX_EPOCHS):
        model.train()
        for xb, yb in train_loader:
            xb, yb = xb.to(device), yb.to(device)
            optimizer.zero_grad()
            logits = model(xb)
            loss = criterion(logits, yb)
            loss.backward()
            optimizer.step()

        model.eval()
        val_loss = 0.0
        with torch.no_grad():
            for xb, yb in val_loader:
                xb, yb = xb.to(device), yb.to(device)
                logits = model(xb)
                val_loss += criterion(logits, yb).item()

        val_loss /= len(val_loader)
        print(f"Epoch {epoch+1}/{MAX_EPOCHS} | Val Loss: {val_loss:.4f}")

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            patience_counter = 0
            torch.save(model.state_dict(), "best_gru.pt")
        else:
            patience_counter += 1
            if patience_counter >= PATIENCE:
                print("Early stopping triggered.")
                break

    model.load_state_dict(torch.load("best_gru.pt"))
    return model


def predict_gru(model, history, tid2idx, idx2tid, device="cpu", top_k=5):
    model.eval()
    with torch.no_grad():
        prefix = history[-MAX_SEQ_LEN:]
        x = [tid2idx.get(t, tid2idx["<UNK>"]) for t in prefix]
        if len(x) < MAX_SEQ_LEN:
            x = [tid2idx["<PAD>"]] * (MAX_SEQ_LEN - len(x)) + x
        x_tensor = torch.tensor([x], dtype=torch.long).to(device)
        logits = model(x_tensor)
        probs = torch.softmax(logits, dim=1).cpu().numpy().flatten()
        candidates = []
        for idx, p in enumerate(probs):
            tid = idx2tid.get(idx, "<UNK>")
            if tid not in ("<PAD>", "<UNK>"):
                candidates.append((tid, float(p)))
        candidates.sort(key=lambda x: x[1], reverse=True)
        return candidates[:top_k]


def ensemble_predict(history, mk1, gru_model, tid2idx, idx2tid, device="cpu", top_k=5, gru_weight=0.6):
    mk_preds = mk1.predict(history, tid2idx, top_k=50)
    mk_dict = {tid: score for tid, score in mk_preds}
    gru_preds = predict_gru(gru_model, history, tid2idx, idx2tid, device=device, top_k=50)
    gru_dict = {tid: score for tid, score in gru_preds}

    def minmax_norm(d):
        if not d:
            return {}
        vals = list(d.values())
        min_v, max_v = min(vals), max(vals)
        if max_v == min_v:
            return {k: 1.0 for k in d}
        return {k: (v - min_v) / (max_v - min_v) for k, v in d.items()}

    mk_norm = minmax_norm(mk_dict)
    gru_norm = minmax_norm(gru_dict)

    all_tids = set(mk_norm.keys()) | set(gru_norm.keys())
    ensemble = []
    for tid in all_tids:
        score = gru_weight * gru_norm.get(tid, 0) + (1 - gru_weight) * mk_norm.get(tid, 0)
        ensemble.append((tid, score))
    ensemble.sort(key=lambda x: x[1], reverse=True)
    return ensemble[:top_k]


def apply_tactic_penalty(predictions, current_tid, penalty=0.5):
    """
    FIXED: Only penalize BACKWARD tactic moves.
    Same-tactic transitions are NOT penalized.
    """
    if not current_tid or current_tid not in TID_TO_TACTIC:
        return predictions
    current_tactic = TID_TO_TACTIC[current_tid]
    current_order = TACTIC_ORDER.get(current_tactic, 99)

    adjusted = []
    for tid, score in predictions:
        next_tactic = TID_TO_TACTIC.get(tid, "")
        next_order = TACTIC_ORDER.get(next_tactic, 99)
        if next_order < current_order:
            score *= penalty
        adjusted.append((tid, score))
    adjusted.sort(key=lambda x: x[1], reverse=True)
    return adjusted


def smart_predict(history, mk1, gru_model, tid2idx, idx2tid, device="cpu", top_k=5):
    preds = ensemble_predict(history, mk1, gru_model, tid2idx, idx2tid, device, top_k=10)
    current = history[-1] if history else None
    if current:
        preds = apply_tactic_penalty(preds, current, penalty=0.5)
    return preds[:top_k]


def evaluate_model(model_predict_fn, examples, top_ks=[1, 3, 5]):
    metrics = {f"top_{k}": 0 for k in top_ks}
    metrics["mrr"] = 0.0
    metrics["count"] = 0

    for ex in examples:
        history = ex["prefix"]
        true_target = ex["target"]
        preds = model_predict_fn(history)
        pred_tids = [p[0] for p in preds]

        for k in top_ks:
            if true_target in pred_tids[:k]:
                metrics[f"top_{k}"] += 1

        if true_target in pred_tids:
            rank = pred_tids.index(true_target) + 1
            metrics["mrr"] += 1.0 / rank

        metrics["count"] += 1

    n = metrics["count"]
    for k in top_ks:
        metrics[f"top_{k}"] = metrics[f"top_{k}"] / n if n else 0
    metrics["mrr"] = metrics["mrr"] / n if n else 0
    return metrics


def print_metrics(metrics, label=""):
    print(f"\n=== Metrics: {label} ===")
    print(f"  Top-1 Accuracy : {metrics.get('top_1', 0):.4f}")
    print(f"  Top-3 Accuracy : {metrics.get('top_3', 0):.4f}")
    print(f"  Top-5 Accuracy : {metrics.get('top_5', 0):.4f}")
    print(f"  MRR            : {metrics.get('mrr', 0):.4f}")
    print(f"  Evaluated on   : {metrics.get('count', 0)} examples")


def load_stix_candidates(path):
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    tr = raw.get("technique_relations", {})
    stix_graph = {}
    for tid, info in tr.items():
        related = info.get("related_techniques", {})
        score_dict = {}
        for next_tid, meta in related.items():
            score = meta.get("combined_score", 0.0)
            if score > 0:
                score_dict[next_tid] = score
        if score_dict:
            stix_graph[tid] = score_dict
    return stix_graph


def normalize_scores(score_list):
    if not score_list:
        return []
    scores = [s for _, s in score_list]
    min_s, max_s = min(scores), max(scores)
    if max_s == min_s:
        return [(tid, 1.0) for tid, _ in score_list]
    return [(tid, (s - min_s) / (max_s - min_s)) for tid, s in score_list]


def fuse_predictions(seq_preds, stix_preds, mode="soft", current_tid=None, stix_graph=None, top_k=5):
    """
    seq_preds: list of (tid, prob) from sequence model
    stix_preds: list of (tid, score) from STIX candidate generator (used for hard_intersection only)
    mode: "sequence_only" | "hard_intersection" | "soft"
    """
    seq_dict = {tid: p for tid, p in seq_preds}
    stix_dict = {tid: s for tid, s in stix_preds}

    if mode == "sequence_only":
        return seq_preds[:top_k]

    if mode == "hard_intersection":
        shared = [tid for tid, _ in seq_preds if tid in stix_dict]
        result = [(tid, seq_dict[tid]) for tid in shared]
        result.sort(key=lambda x: x[1], reverse=True)
        return result[:top_k]

    if mode == "soft":
        # NEW: Boost-based fusion.
        # If STIX knows the candidate, give it a small bonus (up to +15%).
        # If STIX doesn't know it, leave the GRU score unchanged.
        if not current_tid or not stix_graph:
            return seq_preds[:top_k]
        
        stix_cands = stix_graph.get(current_tid, {})
        if not stix_cands:
            return seq_preds[:top_k]
        
        max_stix = max(stix_cands.values())
        fused = []
        for tid, p in seq_preds:
            stix_score = stix_cands.get(tid, 0) / max_stix if max_stix else 0
            new_score = p * (1 + 0.15 * stix_score)
            fused.append((tid, new_score))
        
        fused.sort(key=lambda x: x[1], reverse=True)
        return fused[:top_k]

    return seq_preds[:top_k]

def generate_stix_synthetic(stix_graph, supported_tids, num_chains=100, min_len=4, max_len=10, seed=42):
    random.seed(seed)
    supported_set = set(supported_tids)
    starters = [t for t in supported_set if t in stix_graph and stix_graph[t]]
    chains = []
    for i in range(num_chains):
        current = random.choice(starters)
        chain = [current]
        for _ in range(max_len - 1):
            cands = [(t, stix_graph[current][t]) for t in stix_graph.get(current, {}) if t in supported_set and t not in chain]
            if not cands:
                break
            total_score = sum(s for _, s in cands)
            probs = [s / total_score for _, s in cands]
            current = random.choices([t for t, _ in cands], weights=probs, k=1)[0]
            chain.append(current)
        if len(chain) >= min_len:
            chains.append({
                "campaign": f"SYNTHETIC-STIX-{i:03d}",
                "source_file": "stix_constrained_generator",
                "sequence": chain,
                "length": len(chain)
            })
    return chains


def main():
    parser = argparse.ArgumentParser(description="Hybrid ATT&CK Chain Prediction Pipeline")
    parser.add_argument("--sequences", required=True, help="Path to sequences JSON")
    parser.add_argument("--stix", default=None, help="Path to STIX candidate JSON")
    parser.add_argument("--supported", default=None, help="JSON list of supported technique IDs")
    parser.add_argument("--device", default="cpu", help="torch device")
    args = parser.parse_args()

    print("[1] Loading sequences...")
    sequences = load_sequences(args.sequences)
    print(f"    Loaded {len(sequences)} campaign sequences.")

    supported = None
    if args.supported:
        with open(args.supported, "r", encoding="utf-8") as f:
            supported = set(json.load(f))
        print(f"    Restricted to {len(supported)} supported techniques.")

    vocab, tid2idx, idx2tid = build_vocab(sequences, supported)
    print(f"    Vocabulary size: {len(vocab)} (including PAD/UNK)")

    print("[2] Campaign-level split (70/15/15)...")
    train_seqs, val_seqs, test_seqs = campaign_level_split(sequences)
    train_ex = sequences_to_examples(train_seqs)
    val_ex = sequences_to_examples(val_seqs)
    test_ex = sequences_to_examples(test_seqs)
    print(f"    Train: {len(train_ex)} examples from {len(train_seqs)} campaigns")
    print(f"    Val:   {len(val_ex)} examples from {len(val_seqs)} campaigns")
    print(f"    Test:  {len(test_ex)} examples from {len(test_seqs)} campaigns")

    print("\n[3] Training Markov baselines...")
    mk1 = MarkovModel(order=1)
    mk1.fit(train_ex)
    mk2 = MarkovModel(order=2)
    mk2.fit(train_ex)
    mk3 = MarkovModel(order=3)
    mk3.fit(train_ex)

    print("\n[4] Evaluating Markov models on TEST set...")
    for name, model in [("Markov-1", mk1), ("Markov-2", mk2), ("Markov-3", mk3)]:
        mets = evaluate_model(lambda h: model.predict(h, tid2idx, top_k=5), test_ex)
        print_metrics(mets, label=name)

    gru_model = None
    if TORCH_AVAILABLE:
        print("\n[5] Training GRU (unidirectional, no class weights)...")
        train_ds = SequenceDataset(train_ex, tid2idx)
        val_ds = SequenceDataset(val_ex, tid2idx)
        train_loader = DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True)
        val_loader = DataLoader(val_ds, batch_size=BATCH_SIZE)
        gru_model = train_gru(train_loader, val_loader, len(vocab), device=args.device)

        print("\n[6] Evaluating GRU on TEST set...")
        mets_gru = evaluate_model(
            lambda h: predict_gru(gru_model, h, tid2idx, idx2tid, device=args.device, top_k=5),
            test_ex
        )
        print_metrics(mets_gru, label="GRU")

        print("\n[7] Evaluating Ensemble (Markov + GRU)...")
        mets_ens = evaluate_model(
            lambda h: ensemble_predict(h, mk1, gru_model, tid2idx, idx2tid, device=args.device),
            test_ex
        )
        print_metrics(mets_ens, label="Ensemble (Markov + GRU)")

        print("\n[8] Evaluating Ensemble + Tactic Penalty (backward only)...")
        mets_smart = evaluate_model(
            lambda h: smart_predict(h, mk1, gru_model, tid2idx, idx2tid, device=args.device),
            test_ex
        )
        print_metrics(mets_smart, label="Ensemble + Tactic Penalty")

    if args.stix and gru_model:
        print("\n[9] Running fusion modes with STIX candidates...")
        stix_graph = load_stix_candidates(args.stix)

        def fusion_predict(history, mode):
            current = history[-1] if history else None
            seq_preds = predict_gru(gru_model, history, tid2idx, idx2tid, device=args.device, top_k=20)
            stix_preds = []
            if current and current in stix_graph:
                stix_preds = [(tid, score) for tid, score in stix_graph[current].items()]
                stix_preds.sort(key=lambda x: x[1], reverse=True)
                stix_preds = stix_preds[:20]
            return fuse_predictions(seq_preds, stix_preds, mode=mode, current_tid=current, stix_graph=stix_graph, top_k=5)

        for mode in ["sequence_only", "hard_intersection", "soft"]:
            mets = evaluate_model(lambda h: fusion_predict(h, mode), test_ex)
            print_metrics(mets, label=f"Fusion-{mode}")

    print("\n[✓] Pipeline complete.")


if __name__ == "__main__":
    main()