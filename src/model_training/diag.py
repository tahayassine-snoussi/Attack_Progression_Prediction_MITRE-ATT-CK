import json

SUPPORTED_TIDS = {
    'T1590.001', 'T1016', 'T1190', 'T1133', 'T1078', 'T1505.003', 'T1105', 'T1203',
    'T1204', 'T1021.001', 'T1021.002', 'T1021.004', 'T1046', 'T1595.001', 'T1595.002',
    'T1590.002', 'T1592', 'T1083', 'T1018', 'T1049', 'T1110', 'T1110.001', 'T1110.003',
    'T1210', 'T1071.001', 'T1071.004', 'T1572', 'T1095', 'T1041', 'T1048.003', 'T1567',
    'T1048', 'T1039', 'T1213', 'T1071.002', 'T1496', 'T1497', 'T1568.002', 'T1189',
    'T1059.001', 'T1059', 'T1003.001', 'T1003.008', 'T1027', 'T1204.002', 'T1547.001',
    'T1053.005', 'T1543.003', 'T1087.002', 'T1069.002', 'T1059.004', 'T1548.003', 'T1033'
}

# Load original sequences
with open("model_training_data/unit42_sequences.json", "r", encoding="utf-8") as f:
    sequences = json.load(f)

# Filter: keep only sequences where ALL techniques are supported
filtered_sequences = []
for seq in sequences:
    filtered_seq = [t for t in seq["sequence"] if t in SUPPORTED_TIDS]
    if len(filtered_seq) >= 3:  # Need at least 3 to make useful training examples
        filtered_sequences.append({
            "campaign": seq["campaign"],
            "source_file": seq.get("source_file", ""),
            "sequence": filtered_seq,
            "length": len(filtered_seq)
        })

print(f"Original sequences: {len(sequences)}")
print(f"Supported-only sequences: {len(filtered_sequences)}")

# Save filtered sequences
with open("model_training_data/unit42_sequences_filtered.json", "w", encoding="utf-8") as f:
    json.dump(filtered_sequences, f, indent=2)

# Generate filtered training examples
filtered_training = []
for seq in filtered_sequences:
    s = seq["sequence"]
    for i in range(1, len(s)):
        filtered_training.append({
            "campaign": seq["campaign"],
            "source_file": seq.get("source_file", ""),
            "input": s[:i],
            "target": s[i],
            "input_str": " -> ".join(s[:i])
        })

with open("model_training_data/unit42_training_filtered.json", "w", encoding="utf-8") as f:
    json.dump(filtered_training, f, indent=2)

print(f"Filtered training examples: {len(filtered_training)}")