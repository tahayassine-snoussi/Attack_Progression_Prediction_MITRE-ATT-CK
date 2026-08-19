#!/usr/bin/env python3
"""
Unit42 Playbook JSON → Ordered ATT&CK Technique Sequences
Reads STIX 2.0 bundles from playbook_json/ and extracts tactic-ordered chains.
"""

import json
import glob
from pathlib import Path
from collections import defaultdict

# Canonical ATT&CK Enterprise tactic order (used to sort techniques)
TACTIC_ORDER = {
    "reconnaissance": 1,
    "resource-development": 2,
    "initial-access": 3,
    "execution": 4,
    "persistence": 5,
    "privilege-escalation": 6,
    "defense-evasion": 7,
    "credential-access": 8,
    "discovery": 9,
    "lateral-movement": 10,
    "collection": 11,
    "command-and-control": 12,
    "exfiltration": 13,
    "impact": 14,
}

def parse_stix_bundle(filepath):
    """Load a Unit42 STIX 2.0 bundle."""
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)

def extract_sequences(bundle):
    """
    Extract ordered technique sequences from a Unit42 STIX bundle.
    Returns: list of dicts with campaign_name and technique_sequence
    """
    objects = bundle.get("objects", [])
    
    # Index objects by ID
    obj_by_id = {obj["id"]: obj for obj in objects if "id" in obj}
    
    # Collect attack-patterns with their kill-chain phases
    attack_patterns = {}
    for obj in objects:
        if obj.get("type") == "attack-pattern":
            tid = None
            # Extract ATT&CK technique ID from external_references
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    tid = ref.get("external_id")
                    break
            
            # Get tactic from kill_chain_phases
            tactics = []
            for kcp in obj.get("kill_chain_phases", []):
                if kcp.get("kill_chain_name") == "mitre-attack":
                    tactic = kcp.get("phase_name", "").lower().replace(" ", "-")
                    tactics.append(tactic)
            
            attack_patterns[obj["id"]] = {
                "tid": tid,
                "name": obj.get("name", ""),
                "tactics": tactics,
                "tactic_order": min([TACTIC_ORDER.get(t, 99) for t in tactics]) if tactics else 99
            }
    
    # Group relationships by campaign
    campaign_techniques = defaultdict(list)
    for obj in objects:
        if obj.get("type") == "relationship":
            src = obj.get("source_ref", "")
            tgt = obj.get("target_ref", "")
            rel_type = obj.get("relationship_type", "").lower()
            
            # Unit42 playbooks use 'uses' to link campaign→attack-pattern
            if rel_type in ("uses", "indicates", "employs") and tgt in attack_patterns:
                if src in obj_by_id and obj_by_id[src].get("type") == "campaign":
                    campaign_techniques[src].append(attack_patterns[tgt])
            # Sometimes direction is reversed
            elif rel_type in ("uses", "indicates", "employs") and src in attack_patterns:
                if tgt in obj_by_id and obj_by_id[tgt].get("type") == "campaign":
                    campaign_techniques[tgt].append(attack_patterns[src])
    
    sequences = []
    for camp_id, techniques in campaign_techniques.items():
        campaign = obj_by_id.get(camp_id, {})
        camp_name = campaign.get("name", camp_id)
        
        # Sort by tactic order, deduplicate while preserving first occurrence
        seen = set()
        ordered = []
        for t in sorted(techniques, key=lambda x: x["tactic_order"]):
            if t["tid"] and t["tid"] not in seen:
                ordered.append(t["tid"])
                seen.add(t["tid"])
        
        if len(ordered) >= 3:  # Only keep chains of length ≥ 3
            sequences.append({
                "campaign": camp_name,
                "source_file": Path(bundle.get("id", "unknown")).name,
                "sequence": ordered,
                "length": len(ordered)
            })
    
    return sequences

def generate_training_examples(sequences):
    """
    Generate sliding-window (prefix → target) training examples.
    """
    examples = []
    for seq in sequences:
        s = seq["sequence"]
        for i in range(1, len(s)):
            prefix = s[:i]
            target = s[i]
            examples.append({
                "campaign": seq["campaign"],
                "source_file": seq["source_file"],
                "input": prefix,
                "target": target,
                "input_str": " → ".join(prefix),
            })
    return examples

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("input_dir", help="Directory containing Unit42 STIX JSON files (e.g., playbook_json/)")
    parser.add_argument("--output-sequences", default="unit42_sequences.json")
    parser.add_argument("--output-training", default="unit42_training.json")
    args = parser.parse_args()
    
    all_sequences = []
    json_files = list(Path(args.input_dir).glob("*.json"))
    print(f"Found {len(json_files)} STIX bundles in {args.input_dir}")
    
    for jf in json_files:
        try:
            bundle = parse_stix_bundle(jf)
            seqs = extract_sequences(bundle)
            all_sequences.extend(seqs)
            print(f"  {jf.name}: {len(seqs)} sequences extracted")
        except Exception as e:
            print(f"  {jf.name}: ERROR - {e}")
    
    all_sequences.sort(key=lambda x: x["campaign"])
    training_examples = generate_training_examples(all_sequences)
    
    with open(args.output_sequences, 'w') as f:
        json.dump(all_sequences, f, indent=2)
    with open(args.output_training, 'w') as f:
        json.dump(training_examples, f, indent=2)
    
    print(f"\nExtracted {len(all_sequences)} campaign sequences")
    print(f"Generated {len(training_examples)} training examples")
    print(f"Saved to {args.output_sequences} and {args.output_training}")

if __name__ == "__main__":
    main()