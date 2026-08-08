import pandas as pd
from attack_scorer import ATTACKConfidenceScorer

# Load YOUR database
df = pd.read_csv("src\\mapping_dataset\\clean_mapping_dataset.csv")

# Run the scorer
scorer = ATTACKConfidenceScorer(
    weight_telemetry=0.50,   # highest
    weight_filter=0.30,      # second
    weight_completeness=0.20 # lowest
)

df_scored = scorer.compute(df)

# Save
df_scored.to_csv("mapping_dataset.csv", index=False)