
"""
ATT&CK Telemetry Mapping Database — Confidence Scoring Engine
===============================================================

Purpose:
    Add static confidence scores to an ATT&CK telemetry-to-technique 
    mapping DataFrame. These scores represent relationship-level confidence
    ONLY. Runtime matching scores are NOT stored here.

Architecture:
    DATABASE LAYER  ->  relationship_strength (static)
    RUNTIME LAYER   ->  runtime_match_score (dynamic, calculated later)

New columns added:
    - telemetry_specificity_score : uniqueness of telemetry across techniques
    - filter_specificity_score    : precision of filter_in conditions
    - completeness_score          : descriptive completeness of the row
    - relationship_strength       : weighted final confidence (0-1)

Usage:
    import pandas as pd
    from attack_scorer import ATTACKConfidenceScorer

    df = pd.read_csv("your_telemetry_database.csv")
    scorer = ATTACKConfidenceScorer(
        weight_telemetry=0.50,
        weight_filter=0.30,
        weight_completeness=0.20
    )
    df_scored = scorer.compute(df)
    df_scored.to_csv("scored_database.csv", index=False)
"""

import pandas as pd
import numpy as np
import re


class ATTACKConfidenceScorer:
    """
    Static confidence scoring for ATT&CK telemetry-to-technique mapping database.
    """

    def __init__(self, 
                 weight_telemetry: float = 0.50,
                 weight_filter: float = 0.30, 
                 weight_completeness: float = 0.20):
        """
        Args:
            weight_telemetry: Weight for telemetry specificity (highest importance)
            weight_filter: Weight for filter specificity (second importance)
            weight_completeness: Weight for completeness (lowest importance)
        """
        assert abs(weight_telemetry + weight_filter + weight_completeness - 1.0) < 1e-6,             "Weights must sum to 1.0"
        self.w_telemetry = weight_telemetry
        self.w_filter = weight_filter
        self.w_completeness = weight_completeness

        # Fields that constitute the "telemetry signature" for specificity
        self.telemetry_signature_cols = [
            'event_id', 'event_name', 'data_source', 
            'data_component', 'log_source', 'channel', 'source'
        ]

        # Fields that constitute "completeness" of telemetry description
        self.completeness_cols = [
            'platform', 'data_source', 'data_component', 
            'event_id', 'event_name', 'event_platform',
            'audit_category', 'audit_sub_category', 'channel', 
            'log_source', 'source', 'filter_in'
        ]

    # ------------------------------------------------------------------
    # 1. telemetry_specificity_score
    # ------------------------------------------------------------------
    def _compute_telemetry_specificity(self, df: pd.DataFrame) -> pd.Series:
        """
        Measures how unique a telemetry signature is across ATT&CK techniques.

        Logic:
            - Build a telemetry signature from key identifying columns
            - Count how many unique technique_ids share this signature
            - Score = 1 / sqrt(count)  [inverse frequency, normalized 0-1]

        Rationale:
            - Event ID 1 (Process Creation) appears in many techniques -> low score
            - Sysmon Event 10 (CreateRemoteThread) appears in few -> high score
        """
        df = df.copy()

        # Build a composite signature string (ignoring NaNs)
        def build_signature(row):
            parts = []
            for col in self.telemetry_signature_cols:
                if col in row.index and pd.notna(row[col]) and str(row[col]).strip():
                    parts.append(str(row[col]).strip().lower())
            return "|".join(parts) if parts else "__empty__"

        df['_telemetry_sig'] = df.apply(build_signature, axis=1)

        # Count unique techniques per signature
        sig_technique_counts = df.groupby('_telemetry_sig')['technique_id'].nunique()

        # Map count back to rows
        df['_technique_count'] = df['_telemetry_sig'].map(sig_technique_counts)

        # Inverse frequency: more techniques = lower score
        raw_score = 1.0 / np.sqrt(df['_technique_count'])
        score = raw_score.clip(0.0, 1.0)

        return score

    # ------------------------------------------------------------------
    # 2. filter_specificity_score
    # ------------------------------------------------------------------
    def _compute_filter_specificity(self, df: pd.DataFrame) -> pd.Series:
        """
        Measures precision of filter_in conditions.

        Scoring rubric:
            0.00 - 0.30 : No filter or empty/whitespace only
            0.30 - 0.60 : Generic keyword mention (single word, no operators)
            0.60 - 0.85 : Contains/like/regex/wildcard conditions
            0.85 - 1.00 : Exact equality conditions (=, ==, equals) with specific values
        """
        def score_filter(val):
            if pd.isna(val) or str(val).strip() == "":
                return 0.10  # No filter

            text = str(val).strip()
            lower = text.lower()

            # Exact equality patterns: "ActionType = CreateRemoteThreadApiCall"
            exact_patterns = [
                r'\b\w+\s*=\s*[^\s,;]+',           # Key = Value
                r'\b\w+\s*==\s*[^\s,;]+',          # Key == Value
                r'\bequals?\s*[:=]\s*[^\s,;]+',     # equals: value
                r'\bis\s+"[^"]+"',                  # is "value"
            ]

            for pat in exact_patterns:
                if re.search(pat, lower):
                    return 0.90 if len(text) > 15 else 0.85

            # Contains/like/regex patterns (medium-high)
            contains_patterns = [
                r'\bcontains?\b',
                r'\blike\b',
                r'\bmatch\b',
                r'\bregex\b',
                r'\bstart\s*with\b',
                r'\bend\s*with\b',
                r'\*',  # wildcard
                r'%',   # SQL-like wildcard
            ]
            for pat in contains_patterns:
                if re.search(pat, lower):
                    return 0.72

            # Multiple conditions (AND/OR) -> medium-high
            if any(op in lower for op in [' and ', ' or ', '&', '|']):
                return 0.65

            # Generic single word or short phrase -> medium
            if len(text.split()) <= 3 and len(text) < 40:
                return 0.42

            # Long descriptive text but no operators -> medium
            return 0.52

        return df['filter_in'].apply(score_filter) if 'filter_in' in df.columns else pd.Series(0.1, index=df.index)

    # ------------------------------------------------------------------
    # 3. completeness_score
    # ------------------------------------------------------------------
    def _compute_completeness(self, df: pd.DataFrame) -> pd.Series:
        """
        Measures how complete and descriptive the telemetry relationship is.

        Logic:
            - Check presence of key telemetry descriptor fields
            - Weighted: core identifiers (event_id, data_source) count more than optional ones
        """
        weights = {
            'event_id': 1.5,
            'event_name': 1.5,
            'data_source': 1.5,
            'data_component': 1.0,
            'platform': 1.0,
            'event_platform': 1.0,
            'channel': 0.8,
            'log_source': 0.8,
            'source': 0.8,
            'audit_category': 0.5,
            'audit_sub_category': 0.5,
            'filter_in': 0.5
        }

        scores = []
        for _, row in df.iterrows():
            total_weight = 0.0
            earned_weight = 0.0

            for col, weight in weights.items():
                if col in row.index:
                    total_weight += weight
                    val = row[col]
                    if pd.notna(val) and str(val).strip() and str(val).strip().lower() not in ['nan', 'none', 'null', '']:
                        earned_weight += weight

            if total_weight == 0:
                scores.append(0.0)
            else:
                scores.append(earned_weight / total_weight)

        return pd.Series(scores, index=df.index)

    # ------------------------------------------------------------------
    # 4. relationship_strength
    # ------------------------------------------------------------------
    def compute(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Main entry point. Adds four new score columns to the DataFrame.

        Returns:
            DataFrame with added columns:
                - telemetry_specificity_score
                - filter_specificity_score  
                - completeness_score
                - relationship_strength
        """
        df = df.copy()

        print("[1/4] Computing telemetry_specificity_score...")
        df['telemetry_specificity_score'] = self._compute_telemetry_specificity(df)

        print("[2/4] Computing filter_specificity_score...")
        df['filter_specificity_score'] = self._compute_filter_specificity(df)

        print("[3/4] Computing completeness_score...")
        df['completeness_score'] = self._compute_completeness(df)

        print("[4/4] Computing relationship_strength...")
        df['relationship_strength'] = (
            self.w_telemetry * df['telemetry_specificity_score'] +
            self.w_filter * df['filter_specificity_score'] +
            self.w_completeness * df['completeness_score']
        )

        # Clean up temporary columns if they exist
        for col in ['_telemetry_sig', '_technique_count']:
            if col in df.columns:
                df.drop(columns=[col], inplace=True)

        return df


# ============================================================
# Example Usage (remove or comment out for production import)
# ============================================================

if __name__ == "__main__":
    # Replace with your actual data loading
    # df = pd.read_csv("your_attack_telemetry_database.csv")

    # For demonstration, create minimal sample data
    sample_data = [
        {
            'technique_id': 'T1059.001', 'is_subtechnique': True,
            'technique': 'PowerShell', 'tactic': 'Execution', 'platform': 'Windows',
            'data_source': 'Script', 'data_component': 'Script Execution',
            'relationship_id': 'rel-001', 'name': 'PowerShell 4104 supports T1059.001',
            'source': 'Microsoft-Windows-PowerShell', 'relationship': 'supports',
            'target': 'T1059.001', 'event_id': '4104',
            'event_name': 'Script Block Logging', 'event_platform': 'Windows',
            'audit_category': None, 'audit_sub_category': None,
            'channel': 'Microsoft-Windows-PowerShell/Operational',
            'log_source': 'Microsoft-Windows-PowerShell',
            'filter_in': "ScriptBlockText contains 'Invoke-Mimikatz'",
            'event_identity': None, 'source_identity': 'User',
            'evidence_degree': 'direct', 'evidence_score': 0.7,
            'evidence_confidence_reason': 'Matched on Script Block Logging'
        },
        {
            'technique_id': 'T1622', 'is_subtechnique': False,
            'technique': 'Debugger Evasion', 'tactic': 'Defense Evasion', 'platform': 'Windows',
            'data_source': 'Process', 'data_component': 'OS API Execution',
            'relationship_id': 'rel-002', 'name': 'CreateRemoteThread supports T1622',
            'source': 'Microsoft-Windows-Sysmon', 'relationship': 'supports',
            'target': 'T1622', 'event_id': '8',
            'event_name': 'CreateRemoteThread', 'event_platform': 'Windows',
            'audit_category': None, 'audit_sub_category': None,
            'channel': 'Microsoft-Windows-Sysmon/Operational',
            'log_source': 'Microsoft-Windows-Sysmon',
            'filter_in': "StartModule = null AND StartFunction = null",
            'event_identity': None, 'source_identity': 'SYSTEM',
            'evidence_degree': 'direct', 'evidence_score': 0.85,
            'evidence_confidence_reason': 'Matched on CreateRemoteThread'
        },
        {
            'technique_id': 'T1055', 'is_subtechnique': False,
            'technique': 'Process Injection', 'tactic': 'Defense Evasion', 'platform': 'Windows',
            'data_source': 'Process', 'data_component': 'Process Creation',
            'relationship_id': 'rel-003', 'name': 'Process Creation supports T1055',
            'source': 'Microsoft-Windows-Sysmon', 'relationship': 'supports',
            'target': 'T1055', 'event_id': '1',
            'event_name': 'Process Creation', 'event_platform': 'Windows',
            'audit_category': None, 'audit_sub_category': None,
            'channel': 'Microsoft-Windows-Sysmon/Operational',
            'log_source': 'Microsoft-Windows-Sysmon',
            'filter_in': None,  # No filter -> low specificity
            'event_identity': None, 'source_identity': 'SYSTEM',
            'evidence_degree': 'indirect', 'evidence_score': 0.4,
            'evidence_confidence_reason': 'Matched on Process Creation'
        }
    ]

    df = pd.DataFrame(sample_data)

    scorer = ATTACKConfidenceScorer(
        weight_telemetry=0.50,
        weight_filter=0.30,
        weight_completeness=0.20
    )

    df_scored = scorer.compute(df)

    print("\n=== SCORED RESULTS ===")
    print(df_scored[['technique_id', 'event_id', 'event_name', 'filter_in',
                      'telemetry_specificity_score', 'filter_specificity_score',
                      'completeness_score', 'relationship_strength']].to_string(index=False))
