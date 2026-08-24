# Attack Progression Prediction System

> **An end-to-end security telemetry pipeline that turns Zeek and Wazuh events into MITRE ATT&CK techniques, filters telemetry noise, reconstructs per-user attack chains, and predicts the next likely attacker technique.**

This repository implements a complete **telemetry → semantic mapping → correlation → progression filtering → attack-chain reconstruction → next-technique prediction** pipeline.

The central idea is simple:

```text
Raw security telemetry
        ↓
Zeek / Wazuh collection
        ↓
Decoding + normalization
        ↓
Semantic MITRE ATT&CK mapping
        ↓
Cross-event correlation
        ↓
Progression filtering / noise removal
        ↓
Per-user chronological attack chain
        ↓
GRU + Markov prediction
        ↓
STIX threat-intelligence soft boost
        ↓
Ranked next-technique predictions
```

The system is designed around a practical SOC problem:

> **Given the techniques already observed for a user or attacker, what technique is the attacker most likely to use next?**

Rather than treating every security event as equally important, the pipeline first determines whether an event is meaningful for attack progression. This is important because real telemetry is noisy: the same action may generate multiple alerts, infrastructure systems generate their own events, and some mapped techniques are useful for detection but should not advance an attack sequence.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Problem Statement](#problem-statement)
3. [System Architecture](#system-architecture)
4. [End-to-End Pipeline](#end-to-end-pipeline)
5. [Layer 1: Data Collection](#layer-1-data-collection)
6. [Layer 2: Decoding and Normalization](#layer-2-decoding-and-normalization)
7. [Layer 3: Semantic MITRE ATT&CK Mapping](#layer-3-semantic-mitre-attck-mapping)
8. [Layer 4: Correlation Engines](#layer-4-correlation-engines)
9. [Layer 5: Progression Filtering and Noise Removal](#layer-5-progression-filtering-and-noise-removal)
10. [Layer 6: Attack-Chain Reconstruction](#layer-6-attack-chain-reconstruction)
11. [Layer 7: Attack Progression Prediction](#layer-7-attack-progression-prediction)
12. [GRU Model](#gru-model)
13. [Markov Baseline](#markov-baseline)
14. [STIX Threat-Intelligence Layer](#stix-threat-intelligence-layer)
15. [Fusion Strategy](#fusion-strategy)
16. [Why the Vocabulary Is Filtered](#why-the-vocabulary-is-filtered)
17. [Training Data and Knowledge Sources](#training-data-and-knowledge-sources)
18. [Experimental Results](#experimental-results)
19. [Lab Attack Example](#lab-attack-example)
20. [Configuration](#configuration)
21. [Repository Structure](#repository-structure)
22. [Running the System](#running-the-system)
23. [Outputs](#outputs)
24. [Supported Technique Scope](#supported-technique-scope)
25. [Design Decisions](#design-decisions)
26. [Limitations](#limitations)
27. [Future Work](#future-work)
28. [Research Positioning](#research-positioning)

---

# Project Overview

The system has two major responsibilities:

### 1. Convert telemetry into meaningful ATT&CK events

Zeek and Wazuh generate different kinds of security telemetry. The pipeline:

- collects events from remote monitoring infrastructure;
- decodes raw logs;
- normalizes them into a common event structure;
- semantically maps events to MITRE ATT&CK techniques;
- correlates multiple low-level events when one event alone is insufficient;
- attaches confidence and scoring information to mappings.

### 2. Learn and predict attack progression

After mapping, not every technique should automatically become part of an attack chain.

A dedicated progression layer determines whether the mapped event is relevant to the attacker being tracked. Accepted techniques are inserted into a chronological sequence for the corresponding user.

For example:

```text
T1046 → T1021.004 → T1078 → T1548.003
```

The prediction engine then receives the partial sequence and produces a ranked list:

```text
1. T1496
2. T1071.001
3. T1041
4. T1018
5. T1105
```

The result is therefore not a binary "attacker / not attacker" classification. It is a **next-step prediction system** that can support analyst investigation and threat scoring.

---

# Problem Statement

Traditional rule-based detection answers questions such as:

> "Did this event match a suspicious behavior?"

This project addresses a different question:

> "Given everything this user has already done, what is the attacker likely to do next?"

A security environment may continuously generate:

- SSH connections;
- authentication events;
- network scans;
- DNS traffic;
- HTTP requests;
- system discovery commands;
- privilege escalation events;
- Wazuh rule alerts;
- repeated alerts for the same action;
- legitimate administrative activity;
- infrastructure-generated events.

If all mapped techniques are appended directly to an attack sequence, the sequence becomes polluted.

For example:

```text
T1046 → T1046 → T1078 → T1078 → T1021.004 → T1046 → ...
```

This is technically derived from telemetry, but it is not a useful representation of attacker progression.

The progression layer instead attempts to produce a cleaner representation:

```text
T1046 → T1021.004 → T1078 → T1548.003
```

The prediction model can then learn meaningful transitions instead of learning the behavior of log generators.

---

# System Architecture

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│                         SECURITY TELEMETRY                                   │
│                                                                              │
│     Zeek Server                              Wazuh Server                    │
│     ──────────                              ────────────                    │
│     conn.log                                alerts.json                     │
│     ssh.log                                 archives.json                   │
│     ssl.log                                                                 │
│     http.log                                                                │
│     notice.log                                                              │
│     weird.log                                                               │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                         DATA COLLECTION                                     │
│                                                                              │
│                         SSH Collector                                       │
│                  byte offsets + log rotation handling                       │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                     DECODING + NORMALIZATION                                │
│                                                                              │
│          Zeek decoder                         Wazuh decoder                  │
│               │                                      │                       │
│               └────────────── common event ─────────┘                       │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                     SEMANTIC ATT&CK MAPPING                                 │
│                                                                              │
│       Zeek semantic mapping                 Wazuh semantic mapping           │
│       field conditions                      mapping database                 │
│                                                                              │
│              └───────────────┬────────────────┘                             │
│                              ▼                                              │
│                    Technique + confidence                                   │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                │
                    ┌───────────┴───────────┐
                    ▼                       ▼
          Zeek correlation          Wazuh correlation
          multi-event patterns      source → follow-up
                    │                       │
                    └───────────┬───────────┘
                                ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                   PROGRESSION FILTER / NOISE REMOVAL                        │
│                                                                              │
│   • ignore collector traffic                                                │
│   • reject infrastructure self-alerts                                       │
│   • source-IP validation                                                     │
│   • session/context correlation                                              │
│   • confidence / score thresholds                                            │
│   • source-IP cooldown                                                       │
│   • tactic deduplication                                                     │
│   • technique deduplication                                                  │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                         USER TIMELINE                                        │
│                                                                              │
│       User A: T1046 → T1021.004 → T1078 → T1548.003                         │
│                                                                              │
│       Chronological, filtered, progression-eligible techniques              │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                     ATTACK PROGRESSION MODEL                                │
│                                                                              │
│          ┌─────────────────┐       ┌─────────────────┐                       │
│          │     Markov-1    │       │       GRU       │                       │
│          │      40%        │       │       60%       │                       │
│          └────────┬────────┘       └────────┬────────┘                       │
│                   └──────────────┬──────────┘                                │
│                                  ▼                                           │
│                         Ensemble prediction                                  │
│                                  │                                           │
│                                  ▼                                           │
│                         STIX soft boost                                      │
│                                  │                                           │
│                                  ▼                                           │
│                         Ranked Top-K output                                  │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

# End-to-End Pipeline

The production pipeline is divided into explicit layers.

```text
1. Collect
   ↓
2. Decode
   ↓
3. Normalize
   ↓
4. Map
   ↓
5. Correlate
   ↓
6. Filter
   ↓
7. Build user chain
   ↓
8. Predict next technique
   ↓
9. Store prediction
```

A key architectural principle is the separation between:

```text
Telemetry knowledge
        +
Semantic mapping
        +
Attack progression
        +
Prediction
```

The mapping layer answers:

> "What ATT&CK behavior does this event represent?"

The progression layer answers:

> "Should this behavior become part of the attack chain?"

The prediction layer answers:

> "Given the chain so far, what is likely to happen next?"

Keeping these responsibilities separate prevents the prediction model from becoming dependent on raw telemetry noise.

---

# Layer 1: Data Collection

## SSH-Based Remote Collection

The collector connects to the monitoring infrastructure using SSH and tails configured log files incrementally.

The collector uses byte offsets rather than repeatedly reading complete files.

This provides:

- incremental processing;
- efficient collection;
- log rotation awareness;
- reduced duplicate processing;
- stateful continuation between iterations.

Offsets are committed only after successful processing. If progression processing fails, the corresponding offset is not committed, allowing the event to be processed again.

## Zeek Sources

Current lab pipeline sources include:

| Source | Log |
|---|---|
| Zeek | `conn.log` |
| Zeek | `ssh.log` |
| Zeek | `ssl.log` |
| Zeek | `http.log` |
| Zeek | `notice.log` |
| Zeek | `weird.log` |

Typical Zeek telemetry provides network-level context such as:

- source and destination IPs;
- ports;
- protocols;
- connection metadata;
- SSH activity;
- TLS activity;
- HTTP activity;
- notices;
- anomalous network events.

## Wazuh Sources

| Source | Log |
|---|---|
| Wazuh | `alerts.json` |
| Wazuh | `archives.json` |

Wazuh provides host-level security telemetry and rule-based alerts that complement Zeek's network visibility.

The two sources are intentionally retained as separate pipelines before being integrated into the progression layer.

---

# Layer 2: Decoding and Normalization

Raw logs are decoded into a common normalized event structure.

Schemas are maintained under:

```text
src/decoder/schemas/zeek/
src/decoder/schemas/wazuh/
```

A normalized event follows the general structure:

```json
{
  "telemetry_source": "Zeek",
  "log_type": "ssh.log",
  "timestamp": "2026-08-23T20:01:34.191+00:00",
  "decoded_fields": {
    "id.orig_h": "192.168.56.40",
    "id.resp_h": "192.168.56.30"
  },
  "id": "...",
  "raw_event": {}
}
```

The important design decision is that the semantic mapping layer does not have to understand every raw log format independently.

Instead:

```text
Raw Zeek/Wazuh format
        ↓
Normalized event
        ↓
Semantic interpretation
```

This makes the mapping and progression layers easier to maintain.

---

# Layer 3: Semantic MITRE ATT&CK Mapping

The project uses a semantic mapping layer between normalized telemetry and MITRE ATT&CK.

The mapping databases describe what telemetry characteristics correspond to ATT&CK techniques.

The mapping process is not simply:

```text
log type → technique
```

It can use multiple event fields and conditions to determine whether a technique is supported by the observed telemetry.

A mapping can contain:

```json
{
  "technique_id": "T1021.004",
  "technique_name": "SSH",
  "tactic": "Lateral Movement",
  "mapping_id": "ZEK-T1021.004-001",
  "confidence_score": 0.75,
  "score": 0.75
}
```

## Why Semantic Mapping?

The same log type can contain both relevant and irrelevant events.

For example:

```text
ssh.log
   ├── attacker SSH connection
   ├── legitimate administrator SSH connection
   └── infrastructure SSH connection
```

The mapping layer identifies the possible ATT&CK behavior.

The progression filter later decides whether that mapped behavior should advance the attack chain.

This distinction is fundamental to the architecture.

---

# Layer 4: Correlation Engines

Some ATT&CK techniques cannot be reliably inferred from a single event.

The system therefore has dedicated correlation logic for both Zeek and Wazuh.

## Zeek Correlation

The Zeek correlation engine aggregates events using:

- time windows;
- source/destination relationships;
- group keys;
- multi-event behavioral patterns.

This supports detections such as:

```text
many connection attempts
        ↓
port/service scanning
        ↓
T1046 Network Service Discovery
```

Correlation results preserve the underlying events and expose metadata such as:

```json
{
  "mapping_id": "ZEK-T1046-...",
  "attack_technique": {
    "technique_id": "T1046"
  },
  "confidence_score": 0.8,
  "time_group_id": "0",
  "group_key": "('192.168.56.40', '192.168.56.30')",
  "events": []
}
```

## Wazuh Correlation

Wazuh uses source-followup correlation.

The conceptual model is:

```text
Source event
    ↓
establish context
    ↓
Follow-up event
    ↓
confirm behavior
```

For example:

```text
SSH login
    +
shell/command execution
    ↓
context-aware technique mapping
```

The engine uses contextual attributes such as:

- `agent.name`;
- `data.dstuser`;
- source information;
- temporal proximity.

An important protection is that an event is never correlated with itself.

---

# Layer 5: Progression Filtering and Noise Removal

This layer was introduced specifically to solve a major problem in attack-chain construction:

> **A correct telemetry-to-technique mapping is not automatically a correct attack-progression event.**

A technique may be correctly mapped but still be unsuitable for the attack sequence because it was generated by:

- the collector;
- infrastructure;
- a Wazuh server self-alert;
- repeated telemetry;
- a duplicated alert;
- a technique already represented in the chain;
- a scan burst;
- an event without sufficient attacker attribution.

The progression filter is configuration-driven.

## Filtering Pipeline

The rules are evaluated in a controlled order:

```text
Mapped event
    │
    ├── Ignore collector/source IP?
    │       └── reject
    │
    ├── Infrastructure self-alert?
    │       └── reject
    │
    ├── Session correlation applicable?
    │       └── recover contextual technique
    │
    ├── Confidence / score threshold?
    │       └── reject if insufficient
    │
    ├── Attacker source-IP requirement?
    │       └── reject if attribution fails
    │
    ├── Source-IP cooldown?
    │       └── reject duplicate burst
    │
    ├── Tactic already represented?
    │       └── reject if configured
    │
    └── Technique already in sequence?
            └── reject unless repeats are allowed
```

## Current Lab Rules

The lab configuration includes logic for:

- ignoring collector traffic;
- rejecting Wazuh infrastructure self-alerts;
- requiring the attacker source IP for selected techniques;
- accepting local techniques that naturally have no network source IP;
- session-aware handling of `T1548.003`;
- source-IP cooldown;
- tactic-level deduplication;
- technique-level deduplication.

Example:

```json
{
  "filter_rules": {
    "by_technique": {
      "T1021.004": {
        "require_attacker_source_ip": true
      },
      "T1078": {
        "require_attacker_source_ip": true
      },
      "T1046": {
        "require_attacker_source_ip": true
      },
      "T1548.003": {
        "require_attacker_source_ip": false
      }
    }
  }
}
```

This is intentionally **technique-specific**.

For example:

```text
T1046 Network Service Discovery
```

is naturally associated with network-source attribution.

But:

```text
T1548.003 Sudo and Sudo Caching
```

is a host-local privilege escalation behavior and may not contain a useful source IP.

Applying one global IP rule to every technique would therefore destroy valid progression events.

---

# Layer 6: Attack-Chain Reconstruction

Accepted events are converted into a chronological sequence for the relevant user.

The progression store maintains:

```text
attack_events.jsonl
user_sequences.jsonl
predictions.jsonl
```

## Attack Event Record

Every mapped event can be retained with its decision:

```json
{
  "event_id": "...",
  "user_id": "lab_attacker",
  "timestamp": "...",
  "source": "Wazuh",
  "mapping_id": "WAZ-T1548.003-001",
  "technique_id": "T1548.003",
  "technique_name": "Sudo and Sudo Caching",
  "tactic": "Privilege Escalation",
  "confidence": 0.95,
  "score": 1.0,
  "progression_eligible": true,
  "progression_reason": "post_ssh_escalation",
  "progression_rejected_reason": null
}
```

Rejected events are also useful because they provide an audit trail explaining why telemetry did not enter the attack chain.

## User Sequence

The resulting sequence is:

```json
{
  "user_id": "lab_attacker",
  "timestamp": "...",
  "sequence": [
    {
      "technique_id": "T1046",
      "timestamp": "..."
    },
    {
      "technique_id": "T1021.004",
      "timestamp": "..."
    },
    {
      "technique_id": "T1078",
      "timestamp": "..."
    },
    {
      "technique_id": "T1548.003",
      "timestamp": "..."
    }
  ]
}
```

This sequence is the interface between the telemetry pipeline and the machine-learning model.

---

# Layer 7: Attack Progression Prediction

The prediction task is:

```text
Input:
[T1059.001, T1083, T1016]

Output:
[
    T1049,
    T1018,
    T1105,
    ...
]
```

This is a **sequence prediction problem**, not ordinary multi-class classification.

There may be several reasonable next techniques.

Therefore, the system produces a ranked list rather than a single hard class.

---

# GRU Model

The main neural predictor is a unidirectional GRU.

Architecture:

```text
Technique IDs
    ↓
Embedding
    ↓
GRU
    ↓
Dropout
    ↓
Linear layer
    ↓
55-class probability distribution
```

Current configuration:

```python
Embedding dimension = 64
Hidden dimension    = 128
Dropout              = 0.3
```

The model receives up to the latest 20 techniques:

```text
[T1, T2, T3, ..., T20]
```

with `<PAD>` used for shorter histories.

The output is a probability distribution over the supported prediction vocabulary.

The current vocabulary contains **55 actionable techniques** plus `<PAD>` and `<UNK>` tokens in the prediction pipeline.

---

# Markov Baseline

The Markov-1 model is intentionally simple.

It asks:

> "After technique X, which technique most frequently occurred next in the training data?"

For example:

```text
T1016
  ├── T1049  0.40
  ├── T1018  0.25
  ├── T1105  0.15
  └── ...
```

It uses:

- transition counts;
- Laplace smoothing;
- fallback behavior for unseen histories.

Markov-1 is useful because it provides:

1. a strong statistical baseline;
2. a sanity check for the GRU;
3. a low-cost prediction mechanism.

Higher-order Markov models were also evaluated, but Markov-1 provided the strongest simple baseline in the current experiments.

---

# STIX Threat-Intelligence Layer

MITRE ATT&CK STIX is used as a **knowledge graph**, not as a chronological attack sequence dataset.

This distinction is important.

A STIX relationship such as:

```text
APT group ──uses──> T1059
```

does not mean:

```text
T1059 happens immediately before T1105
```

Instead, STIX provides contextual evidence about:

- which threat groups use techniques;
- technique relationships;
- tactic metadata;
- technique co-occurrence;
- threat-intelligence plausibility.

The project builds candidate relationships from ATT&CK group-technique associations.

Candidate scoring can use:

```text
co-occurrence
+
global rarity / discriminative value
```

These scores are used for **candidate relevance**, not treated as direct next-technique probabilities.

This keeps the semantic distinction between:

```text
Threat-intelligence association
```

and:

```text
Chronological attack progression
```

---

# Fusion Strategy

The final predictor combines three complementary sources of evidence.

| Component | Weight / Effect | What it contributes |
|---|---:|---|
| GRU | 60% | Full sequence memory |
| Markov-1 | 40% | Direct transition frequency |
| STIX graph | up to +15% | Threat-intelligence plausibility |

The fusion pipeline is:

```text
                 User history
                      │
          ┌───────────┴───────────┐
          ▼                       ▼
       GRU 60%                Markov 40%
          │                       │
          └───────────┬───────────┘
                      ▼
               Ensemble score
                      │
                      ▼
              STIX soft boost
                      │
                      ▼
                  Top-K
```

The ensemble normalizes model scores before combining them.

Conceptually:

```python
ensemble_score =
    0.60 * normalized_gru_score +
    0.40 * normalized_markov_score
```

Then:

```python
final_score =
    ensemble_score * (1 + 0.15 * normalized_stix_score)
```

The STIX component is deliberately a **soft boost**.

It does not remove candidates merely because ATT&CK does not contain a corresponding relationship.

This is important because threat intelligence is incomplete and the model may learn legitimate progression patterns that are not explicitly represented in the STIX graph.

---

# Why the Vocabulary Is Filtered

The initial prediction vocabulary contained approximately:

```text
275 techniques
```

Only around 12% of these appeared meaningfully in the available real campaign sequences used for training.

The production vocabulary was reduced to:

```text
55 techniques
```

These are techniques represented by the project's monitoring and semantic-mapping scope.

The objective is not to artificially maximize a benchmark score.

It is to make the prediction output useful:

```text
Raw ATT&CK universe
        ↓
Telemetry-supported techniques
        ↓
SOC-actionable prediction vocabulary
```

If the model predicts techniques that the SOC cannot observe or does not support, a mathematically correct prediction can still be operationally useless.

### Vocabulary comparison

| Metric | 275-technique vocabulary | 55-technique vocabulary |
|---|---:|---:|
| Vocabulary | 275 | 55 |
| Random Top-1 baseline | ~0.36% | ~1.8% |
| GRU Top-1 | 12.8% | **25.0%** |
| Fusion-soft Top-1 | 3.8% | **25.0%** |

The filtered vocabulary therefore represents a deliberate **operational constraint**, not merely a preprocessing trick.

---

# Training Data and Knowledge Sources

The progression model uses chronological attack-chain evidence rather than treating ATT&CK STIX relationships as sequences.

The broader research pipeline can incorporate:

- MITRE ATT&CK procedure examples;
- Atomic Red Team executions;
- public APT / intrusion reports;
- analyst-curated attack-flow data;
- public security datasets;
- controlled laboratory executions.

The current model evaluation described below is based on a relatively small collection of campaign sequences.

### Current experiment

```text
Total sequences: 129
Training:        90
Testing:         20
```

The remaining sequences are used according to the experiment's validation/training workflow.

The key limitation is therefore **data volume**, not a lack of model architecture.

---

# Experimental Results

## Final model comparison

| Model | Top-1 | Top-3 | Top-5 | MRR |
|---|---:|---:|---:|---:|
| Markov-1 | 20.7% | 41.4% | 49.1% | 0.313 |
| Markov-2 | 16.4% | 29.3% | 40.5% | 0.249 |
| Markov-3 | 15.5% | 26.7% | 37.1% | 0.222 |
| **GRU** | **25.0%** | **44.8%** | **54.3%** | **0.351** |
| Ensemble (GRU + Markov) | **25.9%** | 43.1% | 50.9% | 0.350 |
| Fusion-soft (STIX boost) | **25.0%** | **45.7%** | **54.3%** | **0.352** |

## Interpretation

### Top-1: 25.0%

The true next technique is ranked first in approximately one out of four evaluated prediction points.

### Top-3: 45.7%

The true next technique appears within the first three candidates nearly half the time.

### Top-5: 54.3%

The true next technique appears in the top five in more than half of the evaluated cases.

### MRR: 0.352

The model's average reciprocal rank indicates that the correct technique is often relatively high in the candidate list.

For SOC usage, Top-5 is particularly useful because analysts can investigate several plausible next actions rather than relying on a single forced prediction.

---

# Why 25% Top-1 Is Meaningful

On a 55-class problem:

```text
Random Top-1 ≈ 1.8%
```

The GRU achieves:

```text
25.0%
```

which is approximately:

```text
14× the random baseline
```

The final system also outperforms the simple Markov-1 baseline.

The result should not be interpreted as "25% of attacks are predictable." It means that, for the evaluated next-technique prediction points, the correct next technique was ranked first 25% of the time.

The dataset is small, so the results should be interpreted as an initial research result rather than a universal performance guarantee.

---

# What Was Tried and Discarded

Several alternatives were evaluated.

| Approach | Result | Observation |
|---|---|---|
| Bidirectional GRU | 18.1% Top-1 | Too many parameters for the available data |
| Class-weighted loss | Worse | Validation loss diverged and common patterns were over-penalized |
| Hard STIX intersection | Below GRU | Removed valid predictions unknown to STIX |
| Tactic penalty | 24.1% vs 25.9% ensemble | Same-tactic transitions are common in real attacks |
| Geometric fusion | 20.7% Top-1 | STIX combined scores dragged down good GRU predictions |
| Unidirectional GRU | **25.0%** | Best neural configuration tested |

The main conclusion is:

> **With only around 129 sequences, increasing model complexity is more likely to overfit than to create useful attack-progression knowledge.**

---

# Lab Attack Example

The pipeline has been tested against a controlled lab scenario involving an attacker VM and a monitored server.

Example attacker:

```text
Kali / attacker VM
192.168.56.40
```

Target:

```text
192.168.56.30
```

## Phase 1: Network Discovery

```bash
nmap -sS 192.168.56.30
```

Zeek observes the network behavior.

The correlation layer identifies:

```text
T1046 - Network Service Discovery
```

The progression filter accepts it because the source matches the configured attacker IP.

Sequence:

```text
T1046
```

---

## Phase 2: SSH Lateral Movement

```bash
ssh taha@192.168.56.30
```

Zeek observes the SSH connection.

The pipeline can produce:

```text
T1021.004 - SSH
```

and Wazuh can independently provide authentication-related evidence such as:

```text
T1078 - Valid Accounts
```

Duplicate mappings from another telemetry source are prevented from repeatedly polluting the progression sequence.

Sequence:

```text
T1046 → T1021.004 → T1078
```

---

## Phase 3: Privilege Escalation

```bash
sudo cat /etc/shadow
```

Wazuh detects the relevant host behavior.

The progression engine accepts:

```text
T1548.003 - Sudo and Sudo Caching
```

using contextual post-SSH logic because the technique does not naturally require a network source IP.

Final observed chain:

```text
T1046
    ↓
T1021.004
    ↓
T1078
    ↓
T1548.003
```

---

# Example Prediction

After the chain:

```text
T1046 → T1021.004 → T1078 → T1548.003
```

the prediction engine can produce:

```text
1. T1496        score=1.0000
2. T1071.001    score=0.9786
3. T1041        score=0.9480
4. T1018        score=0.8823
5. T1105        score=0.8378
```

These predictions should be interpreted as **ranked hypotheses**, not guaranteed future actions.

A SOC workflow can use them to prioritize:

```text
What should I monitor next?
```

rather than:

```text
What definitely happens next?
```

---

# Configuration

The main progression configuration is:

```text
config/progression_config.json
```

Example:

```json
{
  "lab_mode": true,
  "attacker": {
    "user_id": "lab_attacker",
    "source_ips": [
      "192.168.56.40"
    ]
  },
  "ignore_source_ips": [
    "192.168.56.1"
  ],
  "default_require_attacker_source_ip": true,
  "source_ip_cooldown": {
    "enabled": true,
    "window_seconds": 30,
    "exempt_techniques": [
      "T1021.004",
      "T1078"
    ]
  },
  "filter_rules": {
    "global": {
      "min_confidence": 0.0,
      "min_score": 0.0
    },
    "by_technique": {
      "T1021.004": {
        "require_attacker_source_ip": true
      },
      "T1078": {
        "require_attacker_source_ip": true
      },
      "T1046": {
        "require_attacker_source_ip": true
      },
      "T1548.003": {
        "require_attacker_source_ip": false
      }
    },
    "by_tactic": {
      "Initial Access": {
        "max_occurrences_in_sequence": 1
      }
    },
    "deduplication": {
      "window_seconds": 300
    }
  }
}
```

For another environment, the lab-specific attacker IPs and ignored infrastructure addresses must be changed.

---

# Repository Structure

The repository is organized around the pipeline layers.

```text
Attack_Progression_Prediction_MITRE-ATT-CK/
│
├── src/
│   │
│   ├── logs_extraction/
│   │   └── collector.py
│   │       # SSH-based incremental log collection
│   │
│   ├── decoder/
│   │   ├── schemas/
│   │   │   ├── zeek/
│   │   │   └── wazuh/
│   │   └── ...
│   │       # Raw telemetry → normalized events
│   │
│   ├── pipeline/
│   │   ├── zeek_pipeline.py
│   │   │   # Zeek decoding, semantic mapping and correlation
│   │   │
│   │   ├── wazuh_pipeline.py
│   │   │   # Wazuh decoding, deduplication and semantic mapping
│   │   │
│   │   ├── wazuh_correlation.py
│   │   │   # Source/follow-up contextual correlation
│   │   │
│   │   ├── progression.py
│   │   │   # Integration between mappings and progression
│   │   │
│   │   └── progression_filter.py
│   │       # Noise filtering and sequence eligibility
│   │
│   ├── prediction/
│   │   └── predictor.py
│   │       # GRU + Markov + STIX fusion
│   │
│   └── storage/
│       ├── event_store.py
│       └── progression_store.py
│
├── config/
│   └── progression_config.json
│
├── model_training_data/
│   └── ...
│       # Training / evaluation artifacts
│
├── best_gru.pt
│   # Trained GRU weights
│
├── attack_progression_knowledge.json
│   # STIX-derived attack-progression knowledge graph
│
├── mapping_dataset.csv
│   # Mapping dataset
│
├── wazuh_mappingDB.json
│   # Wazuh semantic mapping database
│
├── wazuh_mappingDB_lab.csv
│   # Lab-specific Wazuh mappings
│
├── zeek_semantic_mappingDB.json
│   # Zeek semantic mappings
│
├── zeek_correlation_mappingDB.json
│   # Zeek correlation mappings
│
├── zeek-mapping.md
│   # Zeek mapping documentation
│
├── semantic_test_results.json
│   # Semantic mapping test results
│
├── training_data.ipynb
│   # Training-data preparation
│
└── README.md
```

The exact runtime paths may vary slightly between the research/training layout and the integrated runtime pipeline. The important architectural boundary is the same:

```text
collection
→ decoding
→ mapping
→ correlation
→ progression
→ prediction
```

---

# Running the System

## Prerequisites

Recommended environment:

```text
Python 3.10+
PyTorch
NumPy
SSH access to the Zeek and Wazuh monitoring hosts
```

Install the core ML dependencies:

```bash
pip install torch numpy
```

Install additional dependencies required by the repository's current source tree as needed.

---

## Configure the Lab

Update:

```text
config/progression_config.json
```

Set:

```text
attacker.source_ips
```

to the IP address(es) used by the attacker VM.

Set:

```text
ignore_source_ips
```

for collector or infrastructure traffic that should never advance the attack chain.

---

## Start the Pipeline

The integrated runtime entry point is:

```bash
python main.py
```

The runtime collector then:

```text
1. Connects to configured telemetry sources
2. Reads only newly available log data
3. Decodes raw events
4. Normalizes event fields
5. Performs semantic ATT&CK mapping
6. Runs correlation logic
7. Sends candidate techniques to progression filtering
8. Rejects irrelevant/noisy events
9. Appends accepted techniques to user chains
10. Runs the prediction engine
11. Stores ranked predictions
```

---

# Resetting Progression State

For clean lab experiments:

### Windows PowerShell

```powershell
Remove-Item "data\progression\attack_events.jsonl"
Remove-Item "data\progression\user_sequences.jsonl"
Remove-Item "data\progression\predictions.jsonl"
```

### Linux

```bash
rm data/progression/*.jsonl
```

Resetting progression state is useful when repeating the same controlled attack and evaluating whether the exact same telemetry produces the same progression decisions.

---

# Outputs

The progression layer writes append-only JSONL files.

## `attack_events.jsonl`

Contains both accepted and rejected mapped events.

This provides an audit trail:

```text
event
  ↓
mapping
  ↓
progression decision
  ↓
reason
```

Example:

```json
{
  "event_id": "...",
  "user_id": "lab_attacker",
  "timestamp": "...",
  "source": "Wazuh",
  "technique_id": "T1548.003",
  "confidence": 0.95,
  "progression_eligible": true,
  "progression_reason": "post_ssh_escalation"
}
```

---

## `user_sequences.jsonl`

Contains the chronological attack-chain snapshot per user.

Example:

```json
{
  "user_id": "lab_attacker",
  "sequence": [
    {"technique_id": "T1046"},
    {"technique_id": "T1021.004"},
    {"technique_id": "T1078"},
    {"technique_id": "T1548.003"}
  ]
}
```

---

## `predictions.jsonl`

Stores a prediction snapshot together with the history that produced it.

Example:

```json
{
  "prediction_id": "pred-8c747bf0",
  "user_id": "lab_attacker",
  "timestamp": "...",
  "history": [
    "T1046",
    "T1021.004",
    "T1078",
    "T1548.003"
  ],
  "predictions": [
    {
      "rank": 1,
      "technique_id": "T1496",
      "score": 1.0
    },
    {
      "rank": 2,
      "technique_id": "T1071.001",
      "score": 0.9786
    }
  ]
}
```

This makes the prediction process auditable because every prediction can be tied back to the sequence that existed at prediction time.

---

# Supported Technique Scope

The prediction vocabulary is intentionally restricted to techniques that are supported by the project's telemetry and semantic mapping layer.

The current model vocabulary is:

```text
55 techniques
+
<PAD>
+
<UNK>
```

Examples from the supported lab/telemetry scope include:

| Technique | Name | Tactic |
|---|---|---|
| T1046 | Network Service Discovery | Reconnaissance |
| T1595.002 | Vulnerability Scanning | Reconnaissance |
| T1595.001 | Scanning IP Blocks | Reconnaissance |
| T1590.001 | Domain Properties | Reconnaissance |
| T1016 | System Network Configuration Discovery | Discovery |
| T1049 | System Network Connections Discovery | Discovery |
| T1018 | Remote System Discovery | Discovery |
| T1083 | File and Directory Discovery | Discovery |
| T1033 | System Owner/User Discovery | Discovery |
| T1059 | Command and Scripting Interpreter | Execution |
| T1059.001 | PowerShell | Execution |
| T1059.004 | Unix Shell | Execution |
| T1021.004 | SSH | Lateral Movement |
| T1021.001 | Remote Desktop Protocol | Lateral Movement |
| T1021.002 | SMB/Windows Admin Shares | Lateral Movement |
| T1210 | Exploitation of Remote Services | Lateral Movement |
| T1078 | Valid Accounts | Initial Access |
| T1190 | Exploit Public-Facing Application | Initial Access |
| T1133 | External Remote Services | Initial Access |
| T1548.003 | Sudo and Sudo Caching | Privilege Escalation |
| T1003.001 | LSASS Memory | Credential Access |
| T1003.008 | `/etc/passwd` and `/etc/shadow` | Credential Access |
| T1110 | Brute Force | Credential Access |
| T1110.001 | Password Guessing | Credential Access |
| T1110.003 | Password Spraying | Credential Access |
| T1105 | Ingress Tool Transfer | Command and Control |
| T1071.001 | Web Protocols | Command and Control |
| T1071.002 | File Transfer Protocols | Command and Control |
| T1071.004 | DNS | Command and Control |
| T1095 | Non-Application Layer Protocol | Command and Control |
| T1041 | Exfiltration Over C2 Channel | Exfiltration |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration |
| T1048.003 | Exfiltration Over Unencrypted Non-C2 Protocol | Exfiltration |
| T1496 | Resource Hijacking | Impact |
| T1204 | User Execution | Execution |
| T1204.002 | Malicious File | Execution |
| T1027 | Obfuscated Files or Information | Defense Evasion |
| T1497 | Virtualization/Sandbox Evasion | Defense Evasion |
| T1505.003 | Web Shell | Persistence |
| T1543.003 | Windows Service | Persistence |
| T1547.001 | Registry Run Keys / Startup Folder | Persistence |
| T1567 | Exfiltration Over Web Service | Exfiltration |
| T1039 | Data from Network Shared Drive | Collection |
| T1213 | Data from Information Repositories | Collection |

The exact production prediction vocabulary should always be taken from the repository's `vocab.json` / training artifact rather than assuming that the entire MITRE ATT&CK Enterprise technique universe is supported.

---

# Important Design Decisions

## 1. Mapping is not progression

A semantic mapper can say:

```text
Event → T1078
```

without implying:

```text
T1078 belongs in the attacker's chronological chain.
```

Progression eligibility is a separate decision.

---

## 2. STIX is not treated as chronological truth

ATT&CK STIX relationships are used as threat-intelligence knowledge.

They are not interpreted as:

```text
T1 → T2 → T3
```

unless chronological evidence exists elsewhere.

Sequence evidence should come from sources that actually contain ordering information, such as:

- attack-flow data;
- procedure execution descriptions;
- Atomic Red Team executions;
- APT reports;
- public intrusion datasets;
- controlled laboratory executions.

---

## 3. The prediction vocabulary is constrained by observability

The model predicts techniques that the monitoring stack can actually support.

This creates a deliberate boundary:

```text
ATT&CK universe
       ↓
Telemetry-supported techniques
       ↓
Prediction vocabulary
```

This is preferable to generating technically plausible but operationally invisible predictions.

---

## 4. Noise removal happens before sequence learning

The model should learn:

```text
attacker behavior
```

not:

```text
log-generation behavior
```

Therefore, progression filtering happens before the sequence reaches the GRU.

---

## 5. Multiple telemetry sources are complementary

Zeek and Wazuh provide different views.

```text
Zeek
  → network behavior

Wazuh
  → host / endpoint behavior

Correlation
  → behavior that requires multiple events
```

Combining them allows a technique to be supported by the telemetry source that has the strongest evidence for that behavior.

---

## 6. Duplicate detection is context-aware

A technique appearing twice in raw telemetry does not necessarily represent two attack steps.

The progression layer therefore uses:

- event IDs;
- synthetic IDs when necessary;
- source-IP cooldown;
- tactic limits;
- technique deduplication;
- contextual exceptions.

---

# Limitations

The current system has several important limitations.

## Limited sequence volume

The current evaluation contains approximately:

```text
129 campaign sequences
```

This is small for training a neural sequence model.

Therefore, the current results should be viewed as a strong prototype/research result rather than a universal benchmark.

---

## Public campaign ordering is imperfect

Threat reports frequently describe what an attacker did without providing a perfect timestamped sequence.

Consequently, chronological training data must be assembled carefully.

---

## Technique mapping quality affects prediction quality

The prediction model cannot recover information that was lost upstream.

If:

```text
telemetry
  ↓
wrong ATT&CK mapping
  ↓
wrong attack chain
  ↓
wrong prediction
```

then improving the GRU will not solve the fundamental problem.

This is why the mapping and progression layers are treated as first-class components.

---

## Lab configuration is environment-specific

Rules such as:

```text
attacker.source_ips
ignore_source_ips
```

are appropriate for the controlled lab but should not be copied unchanged into another environment.

---

## Predictions are hypotheses

A Top-1 prediction is not a claim that the technique will definitely occur.

The intended operational interpretation is:

```text
"Prioritize investigation of these likely next behaviors."
```

not:

```text
"The attacker will definitely execute technique X."
```

---

# Future Work

The most important next improvement is increasing the amount and diversity of chronological attack-chain data.

Potential sources include:

### MITRE Attack Flow

Analyst-curated attack-flow representations can provide stronger ordering information.

### Atomic Red Team

Controlled technique executions can provide ground-truth sequence evidence.

### CALDERA

Automated adversary emulation can produce repeatable attack chains in controlled environments.

### Public APT Reports

Procedure-level reports can be converted into ordered technique chains where the report provides sufficient evidence.

### Larger Lab Campaigns

The current lab can be expanded into multiple attack scenarios:

```text
Reconnaissance
    ↓
Initial Access
    ↓
Execution
    ↓
Discovery
    ↓
Credential Access
    ↓
Privilege Escalation
    ↓
Lateral Movement
    ↓
Collection
    ↓
C2 / Exfiltration
    ↓
Impact
```

The goal is not simply to create more data.

The goal is to create **more reliable chronological transitions**.

---

# Path Toward 30%+ Top-1

The current evidence suggests that additional chronological data is likely to be more valuable than increasing model complexity.

A practical target is:

```text
Current
~129 sequences
       ↓
400+ sequences
       ↓
more diverse transitions
       ↓
better generalization
```

Expected research target:

```text
Top-1: approximately 30–35%
Top-5: 60%+
```

These are targets, not guarantees. Actual performance depends on the quality, diversity, and independence of the additional sequences.

---

# Research Positioning

This project separates three problems that are often mixed together:

## Knowledge

```text
MITRE ATT&CK / STIX
```

Provides:

- technique definitions;
- tactics;
- actor-technique associations;
- threat-intelligence relationships.

## Mapping

```text
Zeek / Wazuh telemetry
        ↓
MITRE ATT&CK technique
```

Provides:

- observability;
- semantic interpretation;
- confidence;
- correlation.

## Learning

```text
Chronological attack chains
        ↓
next-technique model
```

Provides:

- transition patterns;
- sequence dependencies;
- next-step prediction.

## Reasoning

```text
Observed user timeline
        ↓
predicted next techniques
        ↓
analyst/SOC decision support
```

This separation makes the system easier to evaluate scientifically.

For example:

```text
Mapping accuracy
```

can be evaluated independently from:

```text
Progression filtering quality
```

and both can be evaluated independently from:

```text
Next-technique prediction
```

---

# Public API

The prediction component can be used independently from the full telemetry pipeline.

Example:

```python
from prediction.predictor import AttackPredictor

predictor = AttackPredictor(
    gru_model_path="best_gru.pt",
    vocab_path="prediction/vocab.json",
    markov_path=None,
    stix_path=None,
    device="cpu"
)

predictions = predictor.predict(
    ["T1046", "T1021.004", "T1078"],
    top_k=5
)

print(predictions)
```

Example output:

```python
[
    ("T1204", 1.0),
    ("T1059.001", 0.83),
    ...
]
```

The predictor requires at least one observed technique.

---

# Performance Summary

| Metric | Result |
|---|---:|
| Prediction vocabulary | **55 techniques** |
| GRU Top-1 | **25.0%** |
| Ensemble Top-1 | **25.9%** |
| Fusion-soft Top-1 | **25.0%** |
| Top-3 | **45.7%** |
| Top-5 | **54.3%** |
| MRR | **0.352** |
| Random Top-1 baseline | **~1.8%** |
| GRU improvement over random | **~14×** |
| Current chronological sequences | **~129** |
| Training sequences | **90** |
| Test sequences | **20** |

---

# Final Pipeline Summary

The complete system can be summarized as:

```text
┌───────────────────────┐
│ Zeek + Wazuh Logs     │
└───────────┬───────────┘
            ↓
┌───────────────────────┐
│ SSH Incremental       │
│ Collection             │
└───────────┬───────────┘
            ↓
┌───────────────────────┐
│ Decode + Normalize    │
└───────────┬───────────┘
            ↓
┌───────────────────────┐
│ Semantic ATT&CK       │
│ Mapping                │
└───────────┬───────────┘
            ↓
┌───────────────────────┐
│ Zeek / Wazuh          │
│ Correlation            │
└───────────┬───────────┘
            ↓
┌───────────────────────┐
│ Progression Filter    │
│ + Noise Removal        │
└───────────┬───────────┘
            ↓
┌───────────────────────┐
│ Per-User Attack Chain │
└───────────┬───────────┘
            ↓
     ┌──────┴──────┐
     ↓             ↓
┌──────────┐  ┌──────────┐
│  Markov  │  │   GRU    │
│   40%    │  │   60%    │
└────┬─────┘  └────┬─────┘
     └──────┬──────┘
            ↓
┌───────────────────────┐
│ Ensemble Prediction   │
└───────────┬───────────┘
            ↓
┌───────────────────────┐
│ STIX Soft Boost       │
│       +15%             │
└───────────┬───────────┘
            ↓
┌───────────────────────┐
│ Ranked Next Techniques│
│        Top-K           │
└───────────────────────┘
```

The resulting architecture is therefore not just a machine-learning model.

It is a complete progression pipeline:

```text
Telemetry
→ Meaning
→ Correlation
→ Attribution
→ Filtering
→ Sequence
→ Prediction
```

The model is only the final stage. The quality of the prediction depends on the quality of every stage before it.
