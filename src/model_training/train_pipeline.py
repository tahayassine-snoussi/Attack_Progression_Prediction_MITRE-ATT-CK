#!/usr/bin/env python3
"""
Hybrid Attack Chain Prediction Pipeline
========================================
Steps:
  1. Campaign-level train/val/test split
  2. First-order Markov baseline (+ higher-order with backoff + Laplace smoothing)
  3. Lightweight GRU sequence model
  4. Three fusion modes with STIX candidates
  5. Evaluation: Top-K accuracy, MRR, Coverage

Usage:
  python src/model_training/train_pipeline.py --sequences model_training_data/unit42_sequences.json --stix attack_progression_knowledge.json
"""

import json
import random
import math
import argparse
from collections import defaultdict, Counter
from pathlib import Path

import numpy as np

# ---------------------------------------------------------------------------
# 0. CONFIGURATION
# ---------------------------------------------------------------------------
SEED = 42
random.seed(SEED)
np.random.seed(SEED)

# Laplace smoothing alpha
ALPHA = 0.1

# GRU hyperparameters
EMBED_DIM = 64
HIDDEN_DIM = 128
DROPOUT = 0.3
BATCH_SIZE = 32
LEARNING_RATE = 1e-3
MAX_EPOCHS = 100
PATIENCE = 10          # early stopping
MAX_SEQ_LEN = 20       # pad / truncate history

# Fusion weights
FUSION_ALPHA = 0.6     # weight for sequence model in soft fusion
FUSION_BETA = 0.4      # weight for STIX score in soft fusion


# ---------------------------------------------------------------------------
# 1. DATA LOADING & CAMPAIGN-LEVEL SPLIT
# ---------------------------------------------------------------------------

def load_sequences(path):
    """Load unit42_sequences.json format."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def build_vocab(sequences, supported_techniques=None):
    """
    Build vocabulary from sequences.
    If supported_techniques is provided, restrict to that set.
    Returns: vocab (list), tid2idx (dict), idx2tid (dict)
    """
    tids = set()
    for seq in sequences:
        for t in seq["sequence"]:
            if supported_techniques is None or t in supported_techniques:
                tids.add(t)
    # Reserve 0 for padding, 1 for UNK
    vocab = ["<PAD>", "<UNK>"] + sorted(tids)
    tid2idx = {t: i for i, t in enumerate(vocab)}
    idx2tid = {i: t for t, i in tid2idx.items()}
    return vocab, tid2idx, idx2tid


def campaign_level_split(sequences, train_ratio=0.70, val_ratio=0.15):
    """
    Split sequences by campaign. Returns train, val, test lists of sequences.
    """
    campaigns = list(sequences)
    random.shuffle(campaigns)
    n = len(campaigns)
    n_train = int(n * train_ratio)
    n_val = int(n * val_ratio)
    train = campaigns[:n_train]
    val = campaigns[n_train:n_train + n_val]
    test = campaigns[n_train + n_val:]
    return train, val, test


def sequences_to_examples(seq_list):
    """
    Convert a list of campaign sequences into (prefix, target) examples.
    """
    examples = []
    for seq in seq_list:
        s = seq["sequence"]
        for i in range(1, len(s)):
            examples.append({
                "campaign": seq["campaign"],
                "prefix": s[:i],
                "target": s[i]
            })
    return examples


# ---------------------------------------------------------------------------
# 2. MARKOV MODEL (1st / 2nd / 3rd order with backoff & Laplace smoothing)
# ---------------------------------------------------------------------------

class MarkovModel:
    def __init__(self, order=1, alpha=ALPHA):
        self.order = order
        self.alpha = alpha
        self.counts = defaultdict(Counter)   # history_tuple -> Counter(next_tech)
        self.totals = defaultdict(int)       # history_tuple -> total_count
        self.vocab_size = 0
        self.tid2idx = None
        self.idx2tid = None

    def fit(self, examples):
        """Train on list of {prefix, target} examples."""
        for ex in examples:
            prefix = ex["prefix"]
            target = ex["target"]
            # Use last `order` techniques as history
            history = tuple(prefix[-self.order:]) if len(prefix) >= self.order else tuple(prefix)
            self.counts[history][target] += 1
            self.totals[history] += 1

    def predict(self, history, vocab_tid2idx, top_k=5):
        """
        Predict next technique given a history list.
        Returns: list of (technique_id, log_prob) sorted descending.
        """
        scores = {}
        # Try current order, then backoff
        for o in range(self.order, 0, -1):
            if len(history) >= o:
                h = tuple(history[-o:])
            else:
                h = tuple(history)
            total = self.totals[h]
            if total == 0:
                continue
            for tid in vocab_tid2idx:
                if tid in ("<PAD>", "<UNK>"):
                    continue
                count = self.counts[h].get(tid, 0)
                prob = (count + self.alpha) / (total + self.alpha * (len(vocab_tid2idx) - 2))
                # Only set if not already set by higher order (backoff priority)
                if tid not in scores:
                    scores[tid] = prob
            if scores:
                break  # stop backoff once we have candidates

        if not scores:
            # Uniform fallback
            for tid in vocab_tid2idx:
                if tid not in ("<PAD>", "<UNK>"):
                    scores[tid] = 1.0 / (len(vocab_tid2idx) - 2)

        sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        return sorted_scores[:top_k]


# ---------------------------------------------------------------------------
# 3. GRU MODEL (PyTorch)
# ---------------------------------------------------------------------------

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
        prefix = ex["prefix"][-self.max_len:]          # truncate if too long
        x = [self.tid2idx.get(t, self.tid2idx["<UNK>"]) for t in prefix]
        # Pad
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
        # x: (batch, seq_len)
        emb = self.embedding(x)               # (batch, seq_len, embed_dim)
        out, hidden = self.gru(emb)           # out: (batch, seq_len, hidden)
        # Take last non-padded output? Simpler: take final hidden state
        # hidden: (1, batch, hidden)
        logits = self.fc(self.dropout(hidden.squeeze(0)))  # (batch, vocab_size)
        return logits


def train_gru(train_loader, val_loader, vocab_size, device="cpu"):
    model = GRUPredictor(vocab_size).to(device)
    criterion = nn.CrossEntropyLoss(ignore_index=0)
    optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE)
    best_val_loss = float("inf")
    patience_counter = 0

    for epoch in range(MAX_EPOCHS):
        model.train()
        train_loss = 0.0
        for xb, yb in train_loader:
            xb, yb = xb.to(device), yb.to(device)
            optimizer.zero_grad()
            logits = model(xb)
            loss = criterion(logits, yb)
            loss.backward()
            optimizer.step()
            train_loss += loss.item()

        model.eval()
        val_loss = 0.0
        with torch.no_grad():
            for xb, yb in val_loader:
                xb, yb = xb.to(device), yb.to(device)
                logits = model(xb)
                loss = criterion(logits, yb)
                val_loss += loss.item()

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
        logits = model(x_tensor)  # (1, vocab_size)
        probs = torch.softmax(logits, dim=1).cpu().numpy().flatten()
        # Exclude PAD and UNK from ranking
        candidates = []
        for idx, p in enumerate(probs):
            tid = idx2tid.get(idx, "<UNK>")
            if tid not in ("<PAD>", "<UNK>"):
                candidates.append((tid, float(p)))
        candidates.sort(key=lambda x: x[1], reverse=True)
        return candidates[:top_k]


# ---------------------------------------------------------------------------
# 4. EVALUATION METRICS
# ---------------------------------------------------------------------------

def evaluate_model(model_predict_fn, examples, top_ks=[1, 3, 5]):
    """
    model_predict_fn: function(history) -> list of (tid, score) sorted descending
    Returns: dict of metrics
    """
    metrics = {f"top_{k}": 0 for k in top_ks}
    metrics["mrr"] = 0.0
    metrics["count"] = 0
    metrics["per_tactic"] = defaultdict(lambda: {"count": 0, "top_5": 0})

    # Simple tactic mapper (you can replace with full ATT&CK mapping)
    # For now we just bucket by first letter as placeholder, or you can load a JSON mapping.
    def get_tactic(tid):
        # TODO: replace with real ATT&CK tactic mapping loaded from enterprise-attack.json
        return "unknown"

    for ex in examples:
        history = ex["prefix"]
        true_target = ex["target"]
        preds = model_predict_fn(history)  # list of (tid, score)
        pred_tids = [p[0] for p in preds]

        # Top-K accuracy
        for k in top_ks:
            if true_target in pred_tids[:k]:
                metrics[f"top_{k}"] += 1

        # MRR
        if true_target in pred_tids:
            rank = pred_tids.index(true_target) + 1
            metrics["mrr"] += 1.0 / rank

        metrics["count"] += 1

    # Normalize
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


# ---------------------------------------------------------------------------
# 5. FUSION MODES
# ---------------------------------------------------------------------------

def load_stix_candidates(path):
    """
    Loads technique_relations from the knowledge graph.
    Returns: {current_tid: {next_tid: combined_score, ...}, ...}
    """
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    tr = raw.get("technique_relations", {})
    stix_graph = {}
    for tid, info in tr.items():
        related = info.get("related_techniques", {})
        score_dict = {}
        for next_tid, meta in related.items():
            # Use 'combined_score' as the ranking metric
            score = meta.get("combined_score", 0.0)
            if score > 0:
                score_dict[next_tid] = score
        if score_dict:
            stix_graph[tid] = score_dict
    return stix_graph


def normalize_scores(score_list):
    """Min-max normalize a list of (tid, score) to [0,1]."""
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
    stix_preds: list of (tid, score) from STIX candidate generator
    mode: "sequence_only" | "hard_intersection" | "soft"
    """
    seq_dict = {tid: p for tid, p in seq_preds}
    stix_dict = {tid: s for tid, s in stix_preds}

    if mode == "sequence_only":
        return seq_preds[:top_k]

    if mode == "hard_intersection":
        shared = [tid for tid, _ in seq_preds if tid in stix_dict]
        # Re-rank by sequence probability
        result = [(tid, seq_dict[tid]) for tid in shared]
        result.sort(key=lambda x: x[1], reverse=True)
        return result[:top_k]

    if mode == "soft":
        # Normalize both to [0,1]
        seq_norm = {tid: p for tid, p in normalize_scores(seq_preds)}
        stix_norm = {tid: s for tid, s in normalize_scores(stix_preds)}
        all_tids = set(seq_norm.keys()) | set(stix_norm.keys())
        fused = []
        for tid in all_tids:
            s = seq_norm.get(tid, 0.0)
            k = stix_norm.get(tid, 0.0)
            # Geometric mean weighted
            score = (s ** FUSION_ALPHA) * (k ** FUSION_BETA)
            fused.append((tid, score))
        fused.sort(key=lambda x: x[1], reverse=True)
        return fused[:top_k]

    return seq_preds[:top_k]


# ---------------------------------------------------------------------------
# 6. MAIN PIPELINE
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Hybrid ATT&CK Chain Prediction Pipeline")
    parser.add_argument("--sequences", required=True, help="Path to unit42_sequences.json")
    parser.add_argument("--stix", default=None, help="Path to STIX candidate JSON (optional)")
    parser.add_argument("--supported", default=None, help="JSON list of supported technique IDs")
    parser.add_argument("--device", default="cpu", help="torch device (cpu or cuda)")
    args = parser.parse_args()

    # 1. Load data
    print("[1] Loading sequences...")
    sequences = load_sequences(args.sequences)
    print(f"    Loaded {len(sequences)} campaign sequences.")

    supported = None
    if args.supported:
        with open(args.supported, "r", encoding="utf-8") as f:
            supported = set(json.load(f))
        print(f"    Restricted to {len(supported)} supported techniques.")

    # 2. Build vocab
    vocab, tid2idx, idx2tid = build_vocab(sequences, supported)
    print(f"    Vocabulary size: {len(vocab)} (including PAD/UNK)")

    # 3. Campaign-level split
    print("[2] Campaign-level split (70/15/15)...")
    train_seqs, val_seqs, test_seqs = campaign_level_split(sequences)
    train_ex = sequences_to_examples(train_seqs)
    val_ex = sequences_to_examples(val_seqs)
    test_ex = sequences_to_examples(test_seqs)
    print(f"    Train: {len(train_ex)} examples from {len(train_seqs)} campaigns")
    print(f"    Val:   {len(val_ex)} examples from {len(val_seqs)} campaigns")
    print(f"    Test:  {len(test_ex)} examples from {len(test_seqs)} campaigns")

    # 4. Train Markov baselines
    print("\n[3] Training Markov baselines...")
    mk1 = MarkovModel(order=1)
    mk1.fit(train_ex)
    mk2 = MarkovModel(order=2)
    mk2.fit(train_ex)
    mk3 = MarkovModel(order=3)
    mk3.fit(train_ex)

    # 5. Evaluate Markov on test set
    print("\n[4] Evaluating Markov models on TEST set...")
    for name, model in [("Markov-1", mk1), ("Markov-2", mk2), ("Markov-3", mk3)]:
        mets = evaluate_model(
            lambda h: model.predict(h, tid2idx, top_k=5),
            test_ex
        )
        print_metrics(mets, label=name)

    # 6. Train GRU (if PyTorch available)
    gru_model = None
    if TORCH_AVAILABLE:
        print("\n[5] Training GRU...")
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
    else:
        print("\n[5] Skipping GRU (PyTorch not installed).")

    # 7. Fusion with STIX (if provided)
    if args.stix and gru_model:
        print("\n[7] Running fusion modes with STIX candidates...")
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