"""
Forensic Analysis Pipeline Orchestrator.
Combines feature extraction, rule-based scoring, VirusTotal lookup, and XAI explainer.
No ML models are involved in the final severity scoring.
"""

import os
import sys
import logging

# Ensure backend directory is in sys.path so relative imports work correctly
backend_dir = os.path.dirname(os.path.abspath(__file__))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

import pandas as pd
import json

from per_process_extractor import extract_per_process_features
from rule_based_scorer import score_all_processes
from combined_scorer import combine_score
from xai_explainer import generate_full_explanation

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def run_full_analysis(
    volatility_results: dict, 
    virustotal_lookup: dict = None, 
    ml_case_level_result: dict = None
) -> list:
    """
    Orchestrate the full process analysis pipeline.
    
    Alur Kerja:
    1. Ekstraksi fitur per-proses dari output Volatility
    2. Scoring rule-based untuk semua proses
    3. Penggabungan dengan data VirusTotal (jika ada) per-proses
    4. Penyusunan penjelasan XAI dengan catatan ML terpisah (jika ada)
    5. Sorting hasil analisis berdasarkan final_score secara descending
    """
    # 1. Feature Extraction
    try:
        df = extract_per_process_features(volatility_results)
    except Exception as e:
        logger.error(f"Error during extract_per_process_features: {e}", exc_info=True)
        return []
        
    # 2. Check if empty
    if df.empty:
        logger.warning("No valid processes detected in the volatility results.")
        return []
        
    # 3. Rule-Based Scoring
    try:
        scored_df = score_all_processes(df)
    except Exception as e:
        logger.error(f"Error during score_all_processes: {e}", exc_info=True)
        return []
        
    # 4. Process each row with individual error handling
    final_explanations = []
    records = scored_df.to_dict(orient='records')
    
    # Lookup handling
    vt_lookup = virustotal_lookup if virustotal_lookup is not None else {}
    
    for row in records:
        pid = row.get('pid')
        name = row.get('name')
        try:
            # Safe parsing of score_breakdown (handles string or list formats)
            score_breakdown = row.get('score_breakdown')
            if isinstance(score_breakdown, str):
                try:
                    score_breakdown = json.loads(score_breakdown)
                except Exception:
                    score_breakdown = []
            elif not isinstance(score_breakdown, list):
                score_breakdown = []
                
            rule_based_result = {
                'pid': pid,
                'name': name,
                'score': row.get('score', 0),
                'severity': row.get('severity', 'clean'),
                'score_breakdown': score_breakdown,
                'whitelist_applied': row.get('whitelist_applied', False),
                'whitelist_reason': row.get('whitelist_reason')
            }
            
            # Retrieve VirusTotal info
            vt_results = vt_lookup.get(pid, [])
            
            # Combine scores (Rule + VT)
            combined_result = combine_score(rule_based_result, vt_results)
            
            # Generate explanation with XAI
            explanation = generate_full_explanation(row, combined_result, ml_case_level_result)
            final_explanations.append(explanation)
            
        except Exception as row_error:
            logger.warning(f"Skipping process PID {pid} ({name}) due to parsing error: {row_error}")
            continue
            
    # 5. Sort list by final_score descending
    final_explanations.sort(key=lambda x: x.get('final_score', 0), reverse=True)
    
    return final_explanations

def get_case_summary(analysis_results: list) -> dict:
    """
    Calculate summary metrics for the case dashboard.
    """
    total_processes = len(analysis_results)
    
    clean_count = 0
    low_count = 0
    medium_count = 0
    high_count = 0
    critical_count = 0
    
    severity_rank = {'clean': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
    highest_severity = 'clean'
    
    for res in analysis_results:
        sev = str(res.get('final_severity', 'clean')).lower()
        if sev == 'clean':
            clean_count += 1
        elif sev == 'low':
            low_count += 1
        elif sev == 'medium':
            medium_count += 1
        elif sev == 'high':
            high_count += 1
        elif sev == 'critical':
            critical_count += 1
            
        if severity_rank.get(sev, 0) > severity_rank.get(highest_severity, 0):
            highest_severity = sev
            
    flagged_count = total_processes - clean_count
    
    return {
        'total_processes': total_processes,
        'clean_count': clean_count,
        'low_count': low_count,
        'medium_count': medium_count,
        'high_count': high_count,
        'critical_count': critical_count,
        'highest_severity': highest_severity,
        'flagged_count': flagged_count
    }

if __name__ == '__main__':
    print("=== TESTING PIPELINE ORCHESTRATOR ===")
    
    # 1. Load the 9 real JSON output files
    plugins = [
        'pslist', 'dlllist', 'handles', 'ldrmodules', 
        'malfind', 'modules', 'svcscan', 'callbacks', 'psscan'
    ]
    
    volatility_results = {}
    print("Loading Volatility 3 JSON output files...")
    for plugin in plugins:
        file_path = os.path.join(backend_dir, f"{plugin}_output.json")
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                volatility_results[plugin] = json.load(f)
            print(f"  [+] Loaded {plugin}_output.json ({len(volatility_results[plugin])} records)")
        except Exception as e:
            print(f"  [!] Failed to load {file_path}: {e}")
            volatility_results[plugin] = []
            
    # 2. Run run_full_analysis with Simplest Scenario (No VT, No ML)
    print("\nRunning run_full_analysis() (No VT, No ML)...")
    results = run_full_analysis(volatility_results, virustotal_lookup=None, ml_case_level_result=None)
    
    # 3. Print Case Summary
    summary = get_case_summary(results)
    print("\n=== CASE SUMMARY ===")
    print(json.dumps(summary, indent=4))
    
    # 4. Print Top 5 Suspicious Processes
    print("\n=== TOP 5 SUSPICIOUS PROCESSES ===")
    for idx, proc in enumerate(results[:5], 1):
        print(f"{idx}. PID: {proc['pid']} | Name: {proc['name']} | Severity: {proc['final_severity'].upper()} | Score: {proc['final_score']}")
        print(f"   Summary: {proc['summary_text']}")
        print("-" * 80)
