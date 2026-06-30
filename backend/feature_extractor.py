"""
Engram - Feature Extractor (REVISI FINAL)
============================================
Mengkonversi output mentah (JSON) dari plugin Volatility 3 menjadi
55 fitur numerik sesuai struktur dataset CIC-MalMem-2022, untuk
dikonsumsi model Isolation Forest (engram_isolation_forest.pkl).

Status validasi (sudah dicek terhadap output JSON asli):
    pslist       -> DIPERBAIKI (filter corrupt row + handle null)
    dlllist      -> OK, tidak ada perubahan
    handles      -> OK, tidak ada perubahan
    ldrmodules   -> OK, tidak ada perubahan
    malfind      -> OK, tidak ada perubahan
    modules      -> OK, tidak ada perubahan
    svcscan      -> OK, tidak ada perubahan
    callbacks    -> OK, tidak ada perubahan
    psxview      -> DIGANTI total. Plugin ini sudah tidak ada di
                    Volatility 3 versi terbaru (2.28.1). Diganti
                    pakai cross-check pslist vs psscan.

Plugin yang dibutuhkan sekarang:
    windows.pslist, windows.dlllist, windows.handles,
    windows.ldrmodules (atau windows.malware.ldrmodules),
    windows.malfind (atau windows.malware.malfind),
    windows.modules, windows.svcscan, windows.callbacks,
    windows.psscan   <- PENGGANTI windows.psxview
"""

import statistics
from typing import List, Dict, Any, Optional


def _safe_mean(values: List[Optional[float]]) -> float:
    """
    Hitung rata-rata dengan aman:
    - skip nilai None/null
    - return 0.0 kalau semua nilai None atau list kosong
    """
    clean_values = [v for v in values if v is not None]
    return float(statistics.mean(clean_values)) if clean_values else 0.0


def _safe_get(record: Dict, *keys, default=None):
    """Ambil nilai dari dict dengan mencoba beberapa kemungkinan nama key."""
    for key in keys:
        if key in record:
            return record[key]
    return default


def _is_valid_process_row(record: Dict) -> bool:
    """
    Filter baris korup yang kadang muncul di hasil scan Volatility 3
    (ditemukan saat testing dump asli — ada row dengan PID/Threads
    bernilai tidak masuk akal, kemungkinan dari memory region yang
    sudah ter-overwrite/garbage).

    Heuristik validasi:
    - PID harus masuk akal (Windows PID asli selalu < 100000)
    - Threads harus masuk akal (tidak ada proses normal dengan
      ribuan/jutaan thread)
    """
    pid = _safe_get(record, 'PID', 'Pid', 'pid', default=0)
    threads = _safe_get(record, 'Threads', 'threads', default=0)

    if pid is None or threads is None:
        return True  # biarkan lolos, akan di-handle sebagai None oleh _safe_mean

    try:
        if int(pid) > 99999:
            return False
        if int(threads) > 10000:
            return False
    except (ValueError, TypeError):
        return False  # kalau tidak bisa di-convert ke angka, kemungkinan corrupt

    return True


# ──────────────────────────────────────────────────────────────
# 1. PSLIST — windows.pslist  [DIPERBAIKI]
# ──────────────────────────────────────────────────────────────
def extract_pslist_features(pslist_output: List[Dict[str, Any]]) -> Dict[str, float]:
    """
    Fitur dari plugin windows.pslist.

    Struktur asli terkonfirmasi (dari output Volatility 3 v2.28.1):
    {
        "CreateTime": "2026-06-02T14:42:21+00:00",
        "ExitTime": null,
        "Handles": null,          <- SELALU null di plugin pslist,
                                     handle count yang sebenarnya
                                     didapat dari plugin handles
        "ImageFileName": "svchost.exe",
        "PID": 5120,
        "PPID": 692,
        "SessionId": 0,
        "Threads": 12,
        "Wow64": false
    }

    PERBAIKAN dari versi sebelumnya:
    1. Filter baris corrupt (PID/Threads tidak masuk akal) sebelum
       dihitung — ditemukan ada garbage row di hasil scan asli.
    2. 'Handles' di pslist selalu null, jadi avg_handlers dihitung
       dari jumlah Threads sebagai proxy (TIDAK IDEAL, lihat catatan
       di bawah) ATAU lebih baik dihitung dari plugin handles secara
       terpisah (lihat extract_handles_features yang punya
       avg_handles_per_proc).

    CATATAN PENTING: dataset CIC-MalMem2022 mendefinisikan
    'pslist.avg_handlers' sebagai rata-rata handle per proses dari
    sumber data pslist. Karena field ini selalu null di Volatility 3
    versi sekarang, kita pakai avg_handles_per_proc dari plugin
    handles sebagai pengganti nilai ini saat assembly fitur final
    (lihat extract_all_features). Di fungsi ini, field tetap
    diproses apa adanya (akan menghasilkan 0.0 kalau dipakai sendiri).
    """
    if not pslist_output:
        return {
            'pslist.nproc': 0, 'pslist.nppid': 0,
            'pslist.avg_threads': 0.0, 'pslist.nprocs64bit': 0,
            'pslist.avg_handlers': 0.0,
        }

    # Filter baris corrupt sebelum diproses lebih lanjut
    valid_rows = [p for p in pslist_output if _is_valid_process_row(p)]

    ppids = [_safe_get(p, 'PPID', 'ppid') for p in valid_rows]
    threads = [_safe_get(p, 'Threads', 'threads', default=0) for p in valid_rows]
    handles = [_safe_get(p, 'Handles', 'handles', default=None) for p in valid_rows]

    unique_ppids = set(ppids) - {None}

    procs_64bit = sum(
        1 for p in valid_rows
        if _safe_get(p, 'Wow64', 'wow64', default=False) is False
    )

    return {
        'pslist.nproc': len(valid_rows),
        'pslist.nppid': len(unique_ppids),
        'pslist.avg_threads': _safe_mean(threads),
        'pslist.nprocs64bit': procs_64bit,
        'pslist.avg_handlers': _safe_mean(handles),  # akan 0.0, di-override di extract_all_features
    }


# ──────────────────────────────────────────────────────────────
# 2. DLLLIST — windows.dlllist  [OK, tidak berubah]
# ──────────────────────────────────────────────────────────────
def extract_dlllist_features(dlllist_output: List[Dict[str, Any]]) -> Dict[str, float]:
    """
    Struktur asli terkonfirmasi:
    {
        "Base": 140699187806208, "LoadCount": -1,
        "LoadTime": "...", "Name": "csrss.exe",
        "PID": 436, "Path": "C:\\Windows\\system32\\csrss.exe",
        "Process": "csrss.exe", "Size": 28672
    }
    Satu row = satu DLL per proses, field PID sesuai asumsi.
    """
    if not dlllist_output:
        return {'dlllist.ndlls': 0, 'dlllist.avg_dlls_per_proc': 0.0}

    total_dlls = len(dlllist_output)

    dlls_per_pid: Dict[Any, int] = {}
    for row in dlllist_output:
        pid = _safe_get(row, 'PID', 'pid')
        dlls_per_pid[pid] = dlls_per_pid.get(pid, 0) + 1

    avg_dlls = _safe_mean(list(dlls_per_pid.values()))

    return {
        'dlllist.ndlls': total_dlls,
        'dlllist.avg_dlls_per_proc': avg_dlls,
    }


# ──────────────────────────────────────────────────────────────
# 3. HANDLES — windows.handles  [OK, tidak berubah]
# ──────────────────────────────────────────────────────────────
def extract_handles_features(handles_output: List[Dict[str, Any]]) -> Dict[str, float]:
    """
    Struktur asli terkonfirmasi:
    {
        "GrantedAccess": 2097151, "HandleValue": 4,
        "Name": "System Pid 4", "Offset": ...,
        "PID": 4, "Process": "System", "Type": "Process"
    }
    Satu row = satu handle. Field PID dan Type sesuai asumsi.

    CATATAN: file handles_output.json bisa SANGAT besar
    (~470rb baris pada dump 8GB testing). Untuk dump produksi yang
    lebih besar, pertimbangkan parsing JSON secara streaming
    (ijson library) daripada json.load() biasa untuk menghindari
    memory spike di backend.
    """
    handle_types_map = {
        'handles.nport': 'Port',
        'handles.nfile': 'File',
        'handles.nevent': 'Event',
        'handles.ndesktop': 'Desktop',
        'handles.nkey': 'Key',
        'handles.nthread': 'Thread',
        'handles.ndirectory': 'Directory',
        'handles.nsemaphore': 'Semaphore',
        'handles.ntimer': 'Timer',
        'handles.nsection': 'Section',
        'handles.nmutant': 'Mutant',
    }

    if not handles_output:
        result = {key: 0 for key in handle_types_map}
        result['handles.nhandles'] = 0
        result['handles.avg_handles_per_proc'] = 0.0
        return result

    result = {}
    for feature_name, handle_type in handle_types_map.items():
        result[feature_name] = sum(
            1 for h in handles_output
            if _safe_get(h, 'Type', 'type') == handle_type
        )

    result['handles.nhandles'] = len(handles_output)

    handles_per_pid: Dict[Any, int] = {}
    for row in handles_output:
        pid = _safe_get(row, 'PID', 'pid')
        handles_per_pid[pid] = handles_per_pid.get(pid, 0) + 1
    result['handles.avg_handles_per_proc'] = _safe_mean(list(handles_per_pid.values()))

    return result


# ──────────────────────────────────────────────────────────────
# 4. LDRMODULES — windows.ldrmodules  [OK, tidak berubah]
# ──────────────────────────────────────────────────────────────
def extract_ldrmodules_features(ldrmodules_output: List[Dict[str, Any]]) -> Dict[str, float]:
    """
    Struktur asli terkonfirmasi:
    {
        "Base": 2003632128, "InInit": false, "InLoad": false,
        "InMem": false, "MappedPath": "\\Windows\\...\\ntdll.dll",
        "Pid": 4, "Process": "System"
    }
    Field 'Pid' (P besar, i kecil) dan InLoad/InInit/InMem
    sesuai asumsi.

    NOTE: plugin ini sudah deprecated, gunakan
    windows.malware.ldrmodules.LdrModules untuk versi Volatility
    yang lebih baru dari 2026-06-07.
    """
    if not ldrmodules_output:
        return {
            'ldrmodules.not_in_load': 0,
            'ldrmodules.not_in_init': 0,
            'ldrmodules.not_in_mem': 0,
            'ldrmodules.not_in_load_avg': 0.0,
            'ldrmodules.not_in_init_avg': 0.0,
            'ldrmodules.not_in_mem_avg': 0.0,
        }

    total = len(ldrmodules_output)

    not_in_load = sum(
        1 for r in ldrmodules_output
        if _safe_get(r, 'InLoad', 'inload', default=True) is False
    )
    not_in_init = sum(
        1 for r in ldrmodules_output
        if _safe_get(r, 'InInit', 'ininit', default=True) is False
    )
    not_in_mem = sum(
        1 for r in ldrmodules_output
        if _safe_get(r, 'InMem', 'inmem', default=True) is False
    )

    return {
        'ldrmodules.not_in_load': not_in_load,
        'ldrmodules.not_in_init': not_in_init,
        'ldrmodules.not_in_mem': not_in_mem,
        'ldrmodules.not_in_load_avg': not_in_load / total if total else 0.0,
        'ldrmodules.not_in_init_avg': not_in_init / total if total else 0.0,
        'ldrmodules.not_in_mem_avg': not_in_mem / total if total else 0.0,
    }


# ──────────────────────────────────────────────────────────────
# 5. MALFIND — windows.malfind  [OK, tidak berubah]
# ──────────────────────────────────────────────────────────────
def extract_malfind_features(malfind_output: List[Dict[str, Any]]) -> Dict[str, float]:
    """
    Struktur asli terkonfirmasi:
    {
        "CommitCharge": 269, "Disasm": "...", "End VPN": ...,
        "Hexdump": "...", "PID": 2088, "PrivateMemory": 1,
        "Process": "MsMpEng.exe", "Protection": "PAGE_EXECUTE_READWRITE",
        "Start VPN": ..., "Tag": "VadS"
    }
    PID, CommitCharge, Protection sesuai asumsi (tidak ada field
    'Address' terpisah — diganti Start VPN/End VPN, tapi kita tidak
    butuh itu untuk fitur yang dipakai).

    NOTE: plugin ini sudah deprecated, gunakan
    windows.malware.malfind.Malfind untuk versi Volatility yang
    lebih baru dari 2026-06-07.
    """
    if not malfind_output:
        return {
            'malfind.ninjections': 0,
            'malfind.commitCharge': 0,
            'malfind.protection': 0,
            'malfind.uniqueInjections': 0.0,
        }

    ninjections = len(malfind_output)
    total_commit_charge = sum(
        _safe_get(r, 'CommitCharge', 'commitCharge', default=0)
        for r in malfind_output
    )

    rwx_count = sum(
        1 for r in malfind_output
        if 'EXECUTE_READWRITE' in str(_safe_get(r, 'Protection', 'protection', default=''))
    )

    unique_pids = set(_safe_get(r, 'PID', 'pid') for r in malfind_output)

    return {
        'malfind.ninjections': ninjections,
        'malfind.commitCharge': total_commit_charge,
        'malfind.protection': rwx_count,
        'malfind.uniqueInjections': float(len(unique_pids)),
    }


# ──────────────────────────────────────────────────────────────
# 6. PSEUDO-PSXVIEW — pengganti windows.psxview [DIGANTI TOTAL]
# ──────────────────────────────────────────────────────────────
def extract_pseudo_psxview_features(
    pslist_output: List[Dict[str, Any]],
    psscan_output: List[Dict[str, Any]],
) -> Dict[str, float]:
    """
    PENGGANTI windows.psxview yang sudah tidak ada di Volatility 3
    versi terbaru (2.28.1 dan seterusnya).

    Konsep asli psxview: cross-check proses dari 7 sumber data
    berbeda (pslist, eprocess_pool, ethread_pool, pspcid_list,
    csrss_handles, session, deskthrd). Proses yang TIDAK MUNCUL di
    salah satu sumber = indikasi proses disembunyikan (DKOM/rootkit).

    Implementasi pengganti: kita hanya punya 2 sumber data yang
    valid untuk cross-check di versi Volatility ini:
        - windows.pslist  (proses dari linked-list, bisa di-unlink
          oleh rootkit)
        - windows.psscan   (proses dari pool scanning, lebih sulit
          disembunyikan karena scan brute-force ke memory pool)

    Proses yang ADA di psscan TAPI TIDAK ADA di pslist adalah
    sinyal kuat hidden/unlinked process.

    LIMITASI YANG HARUS DISADARI:
    - 11 dari 13 fitur psxview asli (yang butuh sumber data
      eprocess_pool, ethread_pool, pspcid_list, csrss_handles,
      session, deskthrd) TIDAK BISA direplikasi dengan tools yang
      tersedia sekarang. Fitur-fitur itu akan diisi 0 (lihat
      extract_all_features).
    - Hanya 'psxview.not_in_pslist' dan
      'psxview.not_in_pslist_false_avg' yang diisi dengan nilai
      hasil cross-check pslist vs psscan yang sesungguhnya.
    - Ini adalah trade-off yang harus dijelaskan secara transparan
      di proposal/dokumentasi: model tetap menerima 55 fitur input,
      tapi sebagian sinyal psxview tidak tersedia karena keterbatasan
      tooling di versi Volatility 3 saat ini.
    """
    pslist_pids = set(_safe_get(p, 'PID', 'pid') for p in pslist_output)
    psscan_pids = set(_safe_get(p, 'PID', 'pid') for p in psscan_output)

    total_psscan = len(psscan_pids)

    # Proses yang ada di psscan tapi tidak di pslist = "not in pslist"
    not_in_pslist_pids = psscan_pids - pslist_pids
    not_in_pslist_count = len(not_in_pslist_pids)

    return {
        'psxview.not_in_pslist': not_in_pslist_count,
        'psxview.not_in_pslist_false_avg': (
            not_in_pslist_count / total_psscan if total_psscan else 0.0
        ),
        # Fitur di bawah ini TIDAK BISA dihitung tanpa plugin psxview asli.
        # Diisi 0 sebagai placeholder yang transparan (bukan dipalsukan).
        'psxview.not_in_eprocess_pool': 0,
        'psxview.not_in_eprocess_pool_false_avg': 0.0,
        'psxview.not_in_ethread_pool': 0,
        'psxview.not_in_ethread_pool_false_avg': 0.0,
        'psxview.not_in_pspcid_list': 0,
        'psxview.not_in_pspcid_list_false_avg': 0.0,
        'psxview.not_in_csrss_handles': 0,
        'psxview.not_in_csrss_handles_false_avg': 0.0,
        'psxview.not_in_session': 0,
        'psxview.not_in_session_false_avg': 0.0,
        'psxview.not_in_deskthrd': 0,
        'psxview.not_in_deskthrd_false_avg': 0.0,
    }


# ──────────────────────────────────────────────────────────────
# 7. MODULES — windows.modules  [OK, tidak berubah]
# ──────────────────────────────────────────────────────────────
def extract_modules_features(modules_output: List[Dict[str, Any]]) -> Dict[str, float]:
    """
    Struktur asli terkonfirmasi:
    {
        "Base": ..., "Name": "ntoskrnl.exe", "Offset": ...,
        "Path": "\\SystemRoot\\system32\\ntoskrnl.exe", "Size": ...
    }
    Cukup butuh jumlah baris, field lain tidak relevan.
    """
    return {
        'modules.nmodules': len(modules_output) if modules_output else 0,
    }


# ──────────────────────────────────────────────────────────────
# 8. SVCSCAN — windows.svcscan  [OK, tidak berubah]
# ──────────────────────────────────────────────────────────────
def extract_svcscan_features(svcscan_output: List[Dict[str, Any]]) -> Dict[str, float]:
    """
    Struktur asli terkonfirmasi:
    {
        "Binary": "...", "Display": "...", "Name": "sppsvc",
        "Order": 423, "PID": 6916, "Start": "SERVICE_AUTO_START",
        "State": "SERVICE_RUNNING", "Type": "SERVICE_WIN32_OWN_PROCESS"
    }

    CATATAN: field 'Type' kadang berisi GABUNGAN flag dipisah '|',
    contoh: "SERVICE_WIN32_OWN_PROCESS|SERVICE_INTERACTIVE_PROCESS".
    Substring check (keyword in string) yang dipakai di bawah ini
    sudah otomatis aman menangani kasus ini.

    PID bisa null untuk service yang SERVICE_STOPPED — tidak masalah
    karena count_type() tidak bergantung pada PID.
    """
    if not svcscan_output:
        return {
            'svcscan.nservices': 0,
            'svcscan.kernel_drivers': 0,
            'svcscan.fs_drivers': 0,
            'svcscan.process_services': 0,
            'svcscan.shared_process_services': 0,
            'svcscan.interactive_process_services': 0,
            'svcscan.nactive': 0,
        }

    def count_type(keyword: str) -> int:
        return sum(
            1 for s in svcscan_output
            if keyword in str(_safe_get(s, 'Type', 'type', default=''))
        )

    nactive = sum(
        1 for s in svcscan_output
        if 'RUNNING' in str(_safe_get(s, 'State', 'state', default=''))
    )

    return {
        'svcscan.nservices': len(svcscan_output),
        'svcscan.kernel_drivers': count_type('KERNEL_DRIVER'),
        'svcscan.fs_drivers': count_type('FILE_SYSTEM_DRIVER'),
        'svcscan.process_services': count_type('WIN32_OWN_PROCESS'),
        'svcscan.shared_process_services': count_type('WIN32_SHARE_PROCESS'),
        'svcscan.interactive_process_services': count_type('INTERACTIVE_PROCESS'),
        'svcscan.nactive': nactive,
    }


# ──────────────────────────────────────────────────────────────
# 9. CALLBACKS — windows.callbacks  [OK, tidak berubah]
# ──────────────────────────────────────────────────────────────
def extract_callbacks_features(callbacks_output: List[Dict[str, Any]]) -> Dict[str, float]:
    """
    Struktur asli terkonfirmasi:
    {
        "Callback": ..., "Detail": null, "Module": "WdFilter",
        "Symbol": null, "Type": "PspLoadImageNotifyRoutine"
    }
    Module dan Type sesuai asumsi. Anonymous = Module null/kosong.
    """
    if not callbacks_output:
        return {
            'callbacks.ncallbacks': 0,
            'callbacks.nanonymous': 0,
            'callbacks.ngeneric': 0,
        }

    nanonymous = sum(
        1 for c in callbacks_output
        if not _safe_get(c, 'Module', 'module', default=None)
    )

    ngeneric = len(callbacks_output) - nanonymous

    return {
        'callbacks.ncallbacks': len(callbacks_output),
        'callbacks.nanonymous': nanonymous,
        'callbacks.ngeneric': ngeneric,
    }


# ──────────────────────────────────────────────────────────────
# MAIN — Gabungkan semua fitur jadi satu dict siap pakai model
# ──────────────────────────────────────────────────────────────
def extract_all_features(volatility_results: Dict[str, List[Dict[str, Any]]]) -> Dict[str, float]:
    """
    Entry point utama. Terima dict hasil semua plugin Volatility 3,
    return 55 fitur siap pakai untuk model Isolation Forest.

    Parameters
    ----------
    volatility_results : dict
        {
            'pslist': [...],
            'dlllist': [...],
            'handles': [...],
            'ldrmodules': [...],
            'malfind': [...],
            'modules': [...],
            'svcscan': [...],
            'callbacks': [...],
            'psscan': [...],   <- WAJIB ADA, pengganti psxview
        }

    Returns
    -------
    dict berisi 55 fitur siap pakai model.
    """
    features = {}

    pslist_data = volatility_results.get('pslist', [])
    handles_data = volatility_results.get('handles', [])
    psscan_data = volatility_results.get('psscan', [])

    features.update(extract_pslist_features(pslist_data))
    features.update(extract_dlllist_features(volatility_results.get('dlllist', [])))

    handles_features = extract_handles_features(handles_data)
    features.update(handles_features)

    # OVERRIDE: pslist.avg_handlers diisi dari handles.avg_handles_per_proc
    # karena field 'Handles' di plugin pslist Volatility 3 versi ini
    # selalu null (lihat catatan di extract_pslist_features)
    features['pslist.avg_handlers'] = handles_features['handles.avg_handles_per_proc']

    features.update(extract_ldrmodules_features(volatility_results.get('ldrmodules', [])))
    features.update(extract_malfind_features(volatility_results.get('malfind', [])))
    features.update(extract_pseudo_psxview_features(pslist_data, psscan_data))
    features.update(extract_modules_features(volatility_results.get('modules', [])))
    features.update(extract_svcscan_features(volatility_results.get('svcscan', [])))
    features.update(extract_callbacks_features(volatility_results.get('callbacks', [])))

    return features


# ──────────────────────────────────────────────────────────────
# Test pakai data dummy
# ──────────────────────────────────────────────────────────────
if __name__ == '__main__':
    import json

    dummy_results = {
        'pslist': [
            {'PID': 4, 'PPID': 0, 'ImageFileName': 'System', 'Threads': 124, 'Handles': None, 'Wow64': False},
            {'PID': 5120, 'PPID': 692, 'ImageFileName': 'svchost.exe', 'Threads': 12, 'Handles': None, 'Wow64': False},
            # baris corrupt seperti yang ditemukan di dump asli
            {'PID': 54962624229035, 'PPID': 248393656645796, 'ImageFileName': 'garbage', 'Threads': 1866976722, 'Handles': None, 'Wow64': True},
        ],
        'psscan': [
            {'PID': 4, 'PPID': 0, 'ImageFileName': 'System'},
            {'PID': 5120, 'PPID': 692, 'ImageFileName': 'svchost.exe'},
            {'PID': 6916, 'PPID': 592, 'ImageFileName': 'hidden.exe'},  # tidak ada di pslist!
        ],
        'dlllist': [
            {'PID': 5120, 'Name': 'kernel32.dll'},
            {'PID': 5120, 'Name': 'ntdll.dll'},
        ],
        'handles': [
            {'PID': 5120, 'Type': 'File'},
            {'PID': 5120, 'Type': 'Key'},
        ],
        'ldrmodules': [
            {'Pid': 5120, 'InLoad': True, 'InInit': True, 'InMem': False},
        ],
        'malfind': [
            {'PID': 5120, 'CommitCharge': 269, 'Protection': 'PAGE_EXECUTE_READWRITE'},
        ],
        'modules': [
            {'Name': 'ntoskrnl.exe'},
        ],
        'svcscan': [
            {'PID': 692, 'Name': 'Schedule', 'Type': 'SERVICE_WIN32_SHARE_PROCESS', 'State': 'SERVICE_RUNNING'},
        ],
        'callbacks': [
            {'Type': 'PspLoadImageNotifyRoutine', 'Module': 'WdFilter'},
        ],
    }

    result = extract_all_features(dummy_results)
    print(f"Total fitur dihasilkan: {len(result)}")
    print(json.dumps(result, indent=2, default=str))

    # Sanity check: harus tepat 55 fitur
    assert len(result) == 55, f"Jumlah fitur tidak sesuai! Harusnya 55, dapat {len(result)}"
    print("\n✓ Jumlah fitur sesuai (55)")
