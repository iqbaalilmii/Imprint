"""
Combined Scorer for Volatility 3 Process Extraction and VirusTotal Reputation Output.
This module combines rule-based process scores with VirusTotal IOC results.
No ML models are involved in this scoring pipeline.
"""

import logging

# Set up simple logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def to_int(val, default=0):
    """Safely convert value to integer."""
    if val is None:
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default

def combine_score(rule_based_result: dict, virustotal_results: list) -> dict:
    """
    Combine rule-based scoring result with VirusTotal IOC scanning results.
    
    Logika penggabungan:
    - Mulai dari rule_based_result['score']
    - Untuk setiap IOC, hitung malicious_ratio = malicious_count / total_engines
    - Jika ada minimal satu IOC dengan malicious_ratio > 0.3 -> +25 bonus
    - Jika ada minimal satu IOC dengan malicious_ratio > 0.6 -> +40 bonus (bukan kumulatif, ambil tertinggi)
    - Cap total score di 100
    - Re-mapping severity dengan threshold: 0-20 clean, 21-40 low, 41-60 medium, 61-80 high, 81-100 critical
    """
    base_score = to_int(rule_based_result.get('score', 0))
    
    max_bonus = 0
    best_ioc = None
    
    # Calculate highest VT bonus
    for ioc in (virustotal_results or []):
        total_engines = to_int(ioc.get('total_engines'))
        malicious_count = to_int(ioc.get('malicious_count'))
        
        if total_engines > 0:
            ratio = malicious_count / total_engines
            
            # ponytail: nested condition determines single highest matching tier.
            if ratio > 0.6:
                bonus = 40
            elif ratio > 0.3:
                bonus = 25
            else:
                bonus = 0
                
            if bonus > max_bonus:
                max_bonus = bonus
                best_ioc = ioc
                
    # Add bonus and cap at 100
    final_score = min(base_score + max_bonus, 100)
    
    # Re-map severity based on final score
    if final_score <= 20:
        final_severity = "clean"
    elif final_score <= 40:
        final_severity = "low"
    elif final_score <= 60:
        final_severity = "medium"
    elif final_score <= 80:
        final_severity = "high"
    else:
        final_severity = "critical"
        
    # Copy score breakdown to prevent side-effects
    score_breakdown = list(rule_based_result.get('score_breakdown', []))
    
    if max_bonus > 0 and best_ioc:
        score_breakdown.append({
            'reason': f"IOC malicious terdeteksi VirusTotal ({best_ioc['malicious_count']}/{best_ioc['total_engines']} engine)",
            'points': max_bonus
        })
        
    return {
        'pid': rule_based_result.get('pid'),
        'name': rule_based_result.get('name'),
        'rule_based_score': base_score,
        'virustotal_bonus': max_bonus,
        'final_score': final_score,
        'final_severity': final_severity,
        'score_breakdown': score_breakdown,
        'whitelist_applied': rule_based_result.get('whitelist_applied', False),
        'whitelist_reason': rule_based_result.get('whitelist_reason'),
        'matched_iocs': virustotal_results
    }

def combine_all_scores(scored_df, virustotal_lookup: dict):
    """
    Apply combine_score to all rows in a DataFrame resulting from score_all_processes().
    Returns a new DataFrame with additional columns: final_score and final_severity.
    """
    import pandas as pd
    
    new_df = scored_df.copy()
    records = new_df.to_dict(orient='records')
    
    final_scores = []
    final_severities = []
    
    for row in records:
        rule_based_res = {
            'pid': row.get('pid'),
            'name': row.get('name'),
            'score': row.get('score'),
            'severity': row.get('severity'),
            'score_breakdown': row.get('score_breakdown'),
            'whitelist_applied': row.get('whitelist_applied'),
            'whitelist_reason': row.get('whitelist_reason')
        }
        pid = row.get('pid')
        vt_results = virustotal_lookup.get(pid, [])
        
        combined = combine_score(rule_based_res, vt_results)
        final_scores.append(combined['final_score'])
        final_severities.append(combined['final_severity'])
        
    new_df['final_score'] = final_scores
    new_df['final_severity'] = final_severities
    
    return new_df

if __name__ == '__main__':
    # Dummy Cases
    # Case 1: rule_based_score rendah (20) tapi ada IOC dengan malicious_ratio tinggi (42/94) -> severity naik signifikan
    case_1_rule = {
        'pid': 101,
        'name': 'chrome.exe',
        'score': 20,
        'severity': 'clean',
        'score_breakdown': [{'reason': 'Process properties check', 'points': 20}],
        'whitelist_applied': False,
        'whitelist_reason': None
    }
    case_1_vt = [
        {'ioc_type': 'ip', 'value': '185.220.101.45', 'malicious_count': 42, 'total_engines': 94}
    ]
    
    # Case 2: rule_based_score tinggi (75) dan tidak ada IOC -> severity tetap
    case_2_rule = {
        'pid': 102,
        'name': 'malicious.exe',
        'score': 75,
        'severity': 'high',
        'score_breakdown': [
            {'reason': 'Process is hidden', 'points': 25},
            {'reason': 'Malfind hits & RWX count > 0', 'points': 30},
            {'reason': 'DLL hidden ratio > 0.5', 'points': 20}
        ],
        'whitelist_applied': False,
        'whitelist_reason': None
    }
    case_2_vt = []
    
    # Case 3: Proses bersih tanpa IOC sama sekali -> tetap clean
    case_3_rule = {
        'pid': 103,
        'name': 'svchost.exe',
        'score': 0,
        'severity': 'clean',
        'score_breakdown': [],
        'whitelist_applied': False,
        'whitelist_reason': None
    }
    case_3_vt = []
    
    test_cases = [
        ("Case 1 (Low Score + Malicious VT -> Severity Upgrade)", case_1_rule, case_1_vt),
        ("Case 2 (High Score + No VT -> No Severity Change)", case_2_rule, case_2_vt),
        ("Case 3 (Clean + No VT -> Clean)", case_3_rule, case_3_vt),
    ]
    
    print("=== TESTING combine_score ===")
    for title, rb, vt in test_cases:
        res = combine_score(rb, vt)
        print(f"\n{title}:")
        print(f"  Process Name: {res['name']} (PID: {res['pid']})")
        print(f"  Original Score/Severity: {res['rule_based_score']} ({rb['severity']})")
        print(f"  VT Bonus: +{res['virustotal_bonus']}")
        print(f"  Final Score/Severity: {res['final_score']} ({res['final_severity']})")
        print(f"  Score Breakdown:")
        for b in res['score_breakdown']:
            print(f"    - {b['reason']}: +{b['points']}")
            
    print("\n=== TESTING combine_all_scores with pandas (if available) ===")
    try:
        import pandas as pd
        # Create a mock scored DataFrame
        df_data = [
            {'pid': 101, 'name': 'chrome.exe', 'score': 20, 'severity': 'clean', 'score_breakdown': [], 'whitelist_applied': False, 'whitelist_reason': None},
            {'pid': 102, 'name': 'malicious.exe', 'score': 75, 'severity': 'high', 'score_breakdown': [], 'whitelist_applied': False, 'whitelist_reason': None},
            {'pid': 103, 'name': 'svchost.exe', 'score': 0, 'severity': 'clean', 'score_breakdown': [], 'whitelist_applied': False, 'whitelist_reason': None}
        ]
        df = pd.DataFrame(df_data)
        lookup = {
            101: case_1_vt,
            102: case_2_vt,
            103: case_3_vt
        }
        df_combined = combine_all_scores(df, lookup)
        print(df_combined[['pid', 'name', 'score', 'severity', 'final_score', 'final_severity']])
    except ImportError:
        print("Pandas is not installed. Skipping DataFrame combine_all_scores test.")
