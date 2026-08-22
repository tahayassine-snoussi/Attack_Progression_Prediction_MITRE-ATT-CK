"""
Production Attack Progression Predictor
Wraps the trained GRU + Markov ensemble with STIX soft boost.
"""

import json
import random
from collections import defaultdict, Counter
from pathlib import Path

import numpy as np

try:
    import torch
    import torch.nn as nn
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    torch = None
    nn = None

# Reproducibility
random.seed(42)
np.random.seed(42)

MAX_SEQ_LEN = 20
EMBED_DIM = 64
HIDDEN_DIM = 128
DROPOUT = 0.3

# Ensemble weights
FUSION_ALPHA = 0.6   # GRU
FUSION_BETA = 0.4    # Markov-1

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


class MarkovModel:
    def __init__(self, order=1, alpha=0.1):
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


if TORCH_AVAILABLE:
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


class AttackPredictor:
    """
    Production predictor.
    Expected artefacts:
        - best_gru.pt          (PyTorch state dict)
        - prediction/vocab.json (JSON list of technique IDs, with <PAD> and <UNK>)
        - markov_counts.json   (optional)
        - stix_candidates.json (optional)
    """
    def __init__(self,
                 gru_model_path="best_gru.pt",
                 vocab_path="src/prediction/vocab.json",
                 markov_path=None,
                 stix_path=None,
                 device="cpu"):
        self.device = device

        # Vocabulary
        self.vocab = self._load_json(vocab_path)
        if not self.vocab:
            raise ValueError(f"Vocabulary not found or empty: {vocab_path}")

        self.tid2idx = {t: i for i, t in enumerate(self.vocab)}
        self.idx2tid = {i: t for t, i in self.tid2idx.items()}

        # GRU
        self.gru_model = None
        if TORCH_AVAILABLE and Path(gru_model_path).exists():
            self.gru_model = GRUPredictor(len(self.vocab)).to(device)
            self.gru_model.load_state_dict(
                torch.load(gru_model_path, map_location=device, weights_only=True)
            )
            self.gru_model.eval()
        elif not TORCH_AVAILABLE:
            print("[PREDICTOR] WARNING: PyTorch not available.")
        else:
            print(f"[PREDICTOR] WARNING: GRU model not found at {gru_model_path}")

        # Markov-1
        self.mk1 = MarkovModel(order=1)
        if markov_path and Path(markov_path).exists():
            self._load_markov(markov_path)
        else:
            print("[PREDICTOR] WARNING: Markov counts not found. Ensemble will use GRU only / uniform fallback.")

        # STIX
        self.stix_graph = {}
        if stix_path and Path(stix_path).exists():
            self.stix_graph = self._load_stix(stix_path)

    # -----------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------
    def _load_json(self, path):
        if not Path(path).exists():
            return None
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _load_markov(self, path):
        data = self._load_json(path)
        if data:
            self.mk1.counts = defaultdict(
                Counter,
                {tuple(k): Counter(v) for k, v in data.get("counts", {}).items()}
            )
            self.mk1.totals = defaultdict(
                int,
                {tuple(k): v for k, v in data.get("totals", {}).items()}
            )

    def _load_stix(self, path):
        raw = self._load_json(path)
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

    # -----------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------
    def predict(self, history, top_k=5):
        """
        history: list of technique IDs (strings), e.g. ["T1021.004", "T1078"]
        Returns: list of (tid, score) sorted descending, length <= top_k
        """
        if not history:
            return []

        # Ensemble (GRU 60% + Markov-1 40%)
        preds = self._ensemble_predict(history, top_k=max(top_k, 10))

        # Tactic penalty (backward moves only)
        current = history[-1] if history else None
        if current:
            preds = self._apply_tactic_penalty(preds, current)

        # STIX soft boost (+15% max)
        preds = self._stix_soft_boost(preds, current, top_k=top_k)

        return preds

    # -----------------------------------------------------------------
    # Internal predictors
    # -----------------------------------------------------------------
    def _predict_gru(self, history, top_k=50):
        if self.gru_model is None:
            return []
        with torch.no_grad():
            prefix = history[-MAX_SEQ_LEN:]
            x = [self.tid2idx.get(t, self.tid2idx["<UNK>"]) for t in prefix]
            if len(x) < MAX_SEQ_LEN:
                x = [self.tid2idx["<PAD>"]] * (MAX_SEQ_LEN - len(x)) + x
            x_tensor = torch.tensor([x], dtype=torch.long).to(self.device)
            logits = self.gru_model(x_tensor)
            probs = torch.softmax(logits, dim=1).cpu().numpy().flatten()
            candidates = []
            for idx, p in enumerate(probs):
                tid = self.idx2tid.get(idx, "<UNK>")
                if tid not in ("<PAD>", "<UNK>"):
                    candidates.append((tid, float(p)))
            candidates.sort(key=lambda x: x[1], reverse=True)
            return candidates[:top_k]

    def _predict_markov(self, history, top_k=50):
        return self.mk1.predict(history, self.tid2idx, top_k=top_k)

    def _ensemble_predict(self, history, top_k=5):
        mk_preds = self._predict_markov(history, top_k=50)
        mk_dict = {tid: score for tid, score in mk_preds}
        gru_preds = self._predict_gru(history, top_k=50)
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
            score = FUSION_ALPHA * gru_norm.get(tid, 0) + FUSION_BETA * mk_norm.get(tid, 0)
            ensemble.append((tid, score))
        ensemble.sort(key=lambda x: x[1], reverse=True)
        return ensemble[:top_k]

    def _apply_tactic_penalty(self, predictions, current_tid, penalty=0.5):
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

    def _stix_soft_boost(self, predictions, current_tid, top_k=5):
        if not current_tid or not self.stix_graph:
            return predictions[:top_k]

        stix_cands = self.stix_graph.get(current_tid, {})
        if not stix_cands:
            return predictions[:top_k]

        max_stix = max(stix_cands.values())
        fused = []
        for tid, p in predictions:
            stix_score = stix_cands.get(tid, 0) / max_stix if max_stix else 0
            new_score = p * (1 + 0.15 * stix_score)
            fused.append((tid, new_score))

        fused.sort(key=lambda x: x[1], reverse=True)
        return fused[:top_k]