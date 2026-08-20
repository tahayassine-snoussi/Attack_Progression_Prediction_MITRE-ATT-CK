import json

# 1. Load your combined/filtered sequences
with open("model_training_data/unit42_sequences_filtered.json", "r", encoding="utf-8") as f:
    sequences = json.load(f)

# 2. Generate sliding-window training examples
training = []
for seq in sequences:
    s = seq["sequence"]
    for i in range(1, len(s)):
        training.append({
            "campaign": seq["campaign"],
            "source_file": seq.get("source_file", ""),
            "input": s[:i],
            "target": s[i],
            "input_str": " -> ".join(s[:i])
        })

# 3. Save
with open("model_training_data/unit42_training_filtered.json", "w", encoding="utf-8") as f:
    json.dump(training, f, indent=2)

print(f"Sequences: {len(sequences)}")
print(f"Training examples: {len(training)}")