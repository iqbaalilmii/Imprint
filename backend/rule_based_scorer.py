"""
Rule-Based Scorer for Volatility 3 Process Extraction Output.
This module determines process severity based purely on rule-based scoring and whitelist checks.
"""

import logging

# Set up simple logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Empirical false-positive whitelist from dump testing
KNOWN_FALSE_POSITIVE_PROCESSES = {
    'MsMpEng.exe': 'Windows Defender — locked memory utk real-time scan',
    'KeePass.exe': 'Password manager — locked memory utk proteksi credential',
    'smartscreen.exe': 'Windows SmartScreen — JIT/sandboxing internal',
    'SearchApp.exe': 'Windows Search — indexing dgn teknik memory khusus',
}

def to_int(val, default=0):
    """Safely convert value to integer."""
    if val is None:
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default

def to_float(val, default=0.0):
    """Safely convert value to float."""
    if val is None:
        return default
    try:
        return float(val)
    except (ValueError, TypeError):
        return default

def to_bool(val):
    """Safely convert value to boolean."""
    if isinstance(val, bool):
        return val
    if val is None:
        return False
    return str(val).lower() in ("true", "1", "yes", "t")

def check_whitelist(name: str) -> tuple:
    """
    Check if a process name matches the empirical whitelist.
    Matches case-insensitively and handles Volatility's 15-character truncation.
    """
    if not name:
        return False, None
    
    name_lower = name.strip().lower()
    if len(name_lower) < 3:
        return False, None
        
    # ponytail: partial matching uses startswith/prefix check to handle 15-char truncation. 
    # If mid-string or regex matching is required in the future, upgrade this loop.
    for fp_name, fp_reason in KNOWN_FALSE_POSITIVE_PROCESSES.items():
        fp_name_lower = fp_name.lower()
        if fp_name_lower.startswith(name_lower) or name_lower.startswith(fp_name_lower):
            return True, fp_reason
            
    return False, None

def score_process(process_row: dict) -> dict:
    """
    Calculate risk score and severity for a single process.
    Accumulative from 0, capped at 100.
    
    Rules:
    - malfind_hits > 0 AND malfind_rwx_count > 0 -> +30 (discounted by 70% if whitelisted)
    - dll_hidden_ratio > 0.5 -> +20
    - is_hidden_process == True -> +25
    - n_dlls == 0 AND n_handles == 0 AND name is not System/Registry/MemCompression -> +15
    """
    pid = process_row.get("pid")
    name = process_row.get("name", "")
    
    # Safe value parsing
    malfind_hits = to_int(process_row.get("malfind_hits"))
    malfind_rwx_count = to_int(process_row.get("malfind_rwx_count"))
    dll_hidden_ratio = to_float(process_row.get("dll_hidden_ratio"))
    is_hidden_process = to_bool(process_row.get("is_hidden_process"))
    n_dlls = to_int(process_row.get("n_dlls"))
    n_handles = to_int(process_row.get("n_handles"))
    
    score_breakdown = []
    whitelist_applied, whitelist_reason = check_whitelist(name)
    
    # Rule 1: Malfind RWX
    if malfind_hits > 0 and malfind_rwx_count > 0:
        base_points = 30
        if whitelist_applied:
            points = int(base_points * 0.3)  # 70% discount (multiply by 0.3)
            reason = f"Malfind hits & RWX detected (Whitelisted: {whitelist_reason})"
        else:
            points = base_points
            reason = "Malfind hits & RWX count > 0"
        score_breakdown.append({"reason": reason, "points": points})
        
    # Rule 2: DLL Hidden Ratio
    if dll_hidden_ratio > 0.5:
        score_breakdown.append({
            "reason": f"DLL hidden ratio ({dll_hidden_ratio}) > 0.5",
            "points": 20
        })
        
    # Rule 3: Hidden Process
    if is_hidden_process:
        score_breakdown.append({
            "reason": "Process is hidden",
            "points": 25
        })
        
    # Rule 4: Zero DLLs and handles for non-system processes
    name_clean = name.strip().lower() if name else ""
    is_system_proc = name_clean in {"system", "registry", "memcompression"}
    if n_dlls == 0 and n_handles == 0 and not is_system_proc:
        score_breakdown.append({
            "reason": "Zero DLLs and zero handles in user-space process",
            "points": 15
        })
        
    # Calculate and cap score
    total_score = sum(item["points"] for item in score_breakdown)
    score = max(0, min(total_score, 100))
    
    # Severity Mapping
    if score <= 20:
        severity = "clean"
    elif score <= 40:
        severity = "low"
    elif score <= 60:
        severity = "medium"
    elif score <= 80:
        severity = "high"
    else:
        severity = "critical"
        
    return {
        "pid": pid,
        "name": name,
        "score": score,
        "severity": severity,
        "score_breakdown": score_breakdown,
        "whitelist_applied": whitelist_applied,
        "whitelist_reason": whitelist_reason
    }

def score_all_processes(df):
    """
    Score all processes in a pandas DataFrame.
    Returns a new DataFrame with additional scoring columns.
    """
    import pandas as pd
    
    # Copy DataFrame to avoid modifying original or producing warnings
    new_df = df.copy()
    
    # Calculate score outputs row-by-row
    results = [score_process(row) for row in new_df.to_dict(orient='records')]
    
    # Insert new columns
    new_df['score'] = [r['score'] for r in results]
    new_df['severity'] = [r['severity'] for r in results]
    new_df['score_breakdown'] = [r['score_breakdown'] for r in results]
    new_df['whitelist_applied'] = [r['whitelist_applied'] for r in results]
    new_df['whitelist_reason'] = [r['whitelist_reason'] for r in results]
    
    return new_df

if __name__ == '__main__':
    # 4 Dummy Cases
    dummy_cases = [
        # Case 1: proses malfind RWX biasa (harus severity tinggi)
        {
            "pid": 2020,
            "name": "explorer.exe",
            "malfind_hits": 4,
            "malfind_rwx_count": 2,
            "dll_hidden_ratio": 0.6,
            "is_hidden_process": True,
            "n_dlls": 10,
            "n_handles": 50
        },
        # Case 2: proses "MsMpEng.exe" dengan malfind hit (harus di-discount, severity turun)
        {
            "pid": 1111,
            "name": "MsMpEng.exe",
            "malfind_hits": 4,
            "malfind_rwx_count": 2,
            "dll_hidden_ratio": 0.6,
            "is_hidden_process": True,
            "n_dlls": 10,
            "n_handles": 50
        },
        # Case 3: proses hidden
        {
            "pid": 3030,
            "name": "random_proc.exe",
            "malfind_hits": 0,
            "malfind_rwx_count": 0,
            "dll_hidden_ratio": 0.1,
            "is_hidden_process": True,
            "n_dlls": 5,
            "n_handles": 12
        },
        # Case 4: proses bersih
        {
            "pid": 4040,
            "name": "svchost.exe",
            "malfind_hits": 0,
            "malfind_rwx_count": 0,
            "dll_hidden_ratio": 0.0,
            "is_hidden_process": False,
            "n_dlls": 80,
            "n_handles": 450
        }
    ]
    
    print("=== TESTING score_process ===")
    scored_results = []
    for idx, case in enumerate(dummy_cases, 1):
        res = score_process(case)
        scored_results.append(res)
        print(f"\nCase {idx}: {res['name']} (PID: {res['pid']})")
        print(f"  Score: {res['score']}")
        print(f"  Severity: {res['severity']}")
        print(f"  Whitelist Applied: {res['whitelist_applied']}")
        print(f"  Whitelist Reason: {res['whitelist_reason']}")
        print(f"  Breakdown:")
        for b in res['score_breakdown']:
            print(f"    - {b['reason']}: +{b['points']}")
            
    print("\n=== TESTING score_all_processes with pandas (if available) ===")
    try:
        import pandas as pd
        df = pd.DataFrame(dummy_cases)
        df_scored = score_all_processes(df)
        print(df_scored[['pid', 'name', 'score', 'severity', 'whitelist_applied']])
    except ImportError:
        print("Pandas is not installed. Skipping DataFrame score_all_processes test.")
