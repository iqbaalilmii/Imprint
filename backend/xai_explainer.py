"""
XAI Explainer for Volatility 3 Scorer.
Provides a clear, human-friendly explanation of process severity calculations,
separating primary rule-based and VT findings from secondary machine learning observations.
"""

import json
import re

DISCLAIMER_TEXT = (
    'Catatan ini berasal dari model Machine Learning yang dilatih dari '
    'dataset publik (CIC-MalMem2022). Dalam pengujian internal kami, model '
    'ini menunjukkan tingkat false positive yang signifikan terhadap sistem '
    'Windows modern karena perbedaan karakteristik environment dengan data '
    'training. Catatan ini TIDAK mempengaruhi severity di atas — gunakan '
    'sebagai sinyal tambahan untuk prioritas investigasi manual, bukan '
    'sebagai bukti malware.'
)

def generate_summary(reasons: list, severity: str) -> str:
    """
    Generate a natural Indonesian summary sentence from the primary reasons list.
    """
    if not reasons:
        return "Tidak ditemukan indikator forensik mencurigakan pada proses ini."
        
    has_malfind = any("malfind" in r['reason'].lower() for r in reasons)
    has_hidden_dll = any("dll hidden ratio" in r['reason'].lower() for r in reasons)
    has_hidden_proc = any("hidden process" in r['reason'].lower() or "is hidden" in r['reason'].lower() for r in reasons)
    has_empty_dll_handles = any("zero dlls" in r['reason'].lower() or "empty dlls" in r['reason'].lower() for r in reasons)
    has_vt = any("virustotal" in r['reason'].lower() or "ioc malicious" in r['reason'].lower() for r in reasons)
    
    triggers = []
    if has_vt:
        # Extract engine details like (42/94)
        vt_reason = next((r['reason'] for r in reasons if "virustotal" in r['reason'].lower() or "ioc malicious" in r['reason'].lower()), "")
        match = re.search(r'\(([^)]+)\)', vt_reason)
        engine_str = f" ({match.group(1)})" if match else ""
        triggers.append(f"terhubung ke IOC yang dikenal malicious di VirusTotal{engine_str}")
    if has_malfind:
        triggers.append("menunjukkan indikator injeksi memori (malfind)")
    if has_hidden_proc:
        triggers.append("berstatus sebagai proses tersembunyi (hidden process)")
    if has_hidden_dll:
        triggers.append("memiliki rasio DLL tersembunyi yang tinggi")
    if has_empty_dll_handles:
        triggers.append("memiliki jumlah DLL dan handles nol yang tidak wajar")
        
    # ponytail: the summary generator uses basic string containment. 
    # If complex/localized rule variations are added later, upgrade this to a translation map.
    if not triggers:
        triggers = [r['reason'].lower() for r in reasons]
        
    if len(triggers) == 1:
        trigger_phrase = triggers[0]
    elif len(triggers) == 2:
        trigger_phrase = f"{triggers[0]} dan {triggers[1]}"
    else:
        trigger_phrase = ", ".join(triggers[:-1]) + f", serta {triggers[-1]}"
        
    # Apply contrast logic for common cases to make explanations feel natural
    contrast = ""
    if has_vt and not has_malfind:
        contrast = ", meskipun tidak menunjukkan indikator injeksi memori"
    elif has_malfind and not has_vt:
        contrast = ", meskipun tidak ditemukan adanya koneksi IOC mencurigakan di VirusTotal"
        
    return f"Proses ini terdeteksi {severity} karena {trigger_phrase}{contrast}."

def generate_full_explanation(process_row: dict, combined_result: dict, ml_case_level_result: dict = None) -> dict:
    """
    Generate a full explanation dict separating primary severity factors from secondary ML hints.
    """
    pid = combined_result.get('pid') or process_row.get('pid')
    name = combined_result.get('name') or process_row.get('name')
    final_severity = combined_result.get('final_severity', 'clean')
    final_score = combined_result.get('final_score', 0)
    primary_reasons = combined_result.get('score_breakdown', [])
    
    # Process Machine Learning observations if provided
    if ml_case_level_result is not None:
        shown = True
        prediction = str(ml_case_level_result.get('prediction', '')).upper()
        if prediction == 'MALWARE':
            ml_flagged_as = 'unusual pattern'
        elif prediction == 'BENIGN':
            ml_flagged_as = 'normal pattern'
        else:
            ml_flagged_as = None
        confidence = ml_case_level_result.get('malware_probability')
    else:
        shown = False
        ml_flagged_as = None
        confidence = None
        
    secondary_ml_note = {
        'shown': shown,
        'ml_flagged_as': ml_flagged_as,
        'confidence': confidence,
        'disclaimer': DISCLAIMER_TEXT
    }
    
    # Generate human-friendly sentence
    summary_text = generate_summary(primary_reasons, final_severity)
    
    return {
        'pid': pid,
        'name': name,
        'final_severity': final_severity,
        'final_score': final_score,
        'primary_reasons': primary_reasons,
        'secondary_ml_note': secondary_ml_note,
        'summary_text': summary_text
    }

if __name__ == '__main__':
    # Case 1: Medium severity with ML warning
    case_1_combined = {
        'pid': 101,
        'name': 'chrome.exe',
        'final_score': 45,
        'final_severity': 'medium',
        'score_breakdown': [
            {'reason': 'Process properties check', 'points': 20},
            {'reason': 'IOC malicious terdeteksi VirusTotal (42/94 engine)', 'points': 25}
        ],
        'whitelist_applied': False,
        'whitelist_reason': None
    }
    case_1_ml = {
        'prediction': 'MALWARE',
        'malware_probability': 0.82
    }
    
    # Case 2: Clean process without ML results
    case_2_combined = {
        'pid': 103,
        'name': 'svchost.exe',
        'final_score': 0,
        'final_severity': 'clean',
        'score_breakdown': [],
        'whitelist_applied': False,
        'whitelist_reason': None
    }
    case_2_ml = None
    
    explanation_1 = generate_full_explanation({}, case_1_combined, case_1_ml)
    explanation_2 = generate_full_explanation({}, case_2_combined, case_2_ml)
    
    print("=== CASE 1 (Medium Severity + ML Flagged MALWARE) ===")
    print(json.dumps(explanation_1, indent=4, ensure_ascii=False))
    
    print("\n=== CASE 2 (Clean Process + No ML Result) ===")
    print(json.dumps(explanation_2, indent=4, ensure_ascii=False))
