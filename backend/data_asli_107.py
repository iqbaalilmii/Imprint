import json
from per_process_extractor import extract_per_process_features
from rule_based_scorer import score_all_processes

def load_json(path):
    with open(path) as f:
        return json.load(f)

volatility_results = {
    'pslist': load_json('pslist_output.json'),
    'dlllist': load_json('dlllist_output.json'),
    'handles': load_json('handles_output.json'),
    'ldrmodules': load_json('ldrmodules_output.json'),
    'malfind': load_json('malfind_output.json'),
    'psscan': load_json('psscan_output.json'),
}

df = extract_per_process_features(volatility_results)
scored_df = score_all_processes(df)

# Urutkan dari severity tertinggi
scored_df_sorted = scored_df.sort_values('score', ascending=False)
print(scored_df_sorted[['pid', 'name', 'score', 'severity', 'whitelist_applied']].to_string())
