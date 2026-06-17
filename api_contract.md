# MemShield Forensics — API Contract
> Dokumen ini adalah "kontrak" antara Frontend dan Backend.
> Jangan mulai coding sebelum baca ini. Jadikan ini context awal saat vibe coding.
> Last updated: Juni 2026

---

## Base URL
```
http://localhost:8000/api
```

---

## Global Response Format
Semua response dari backend mengikuti format ini:
```json
{
  "success": true,
  "data": { ... },
  "error": null
}
```
Jika error:
```json
{
  "success": false,
  "data": null,
  "error": "pesan error yang human-readable"
}
```

---

## 1. CASE MANAGEMENT

### POST `/api/cases`
Buat case baru dan daftarkan path dump.

**Request Body:**
```json
{
  "case_name": "Insiden Server BSSN - 14 Jun 2026",
  "dump_path": "/cases/evidence/dump.raw",
  "analyst_name": "John Doe"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "case_id": "case_20260614_001",
    "case_name": "Insiden Server BSSN - 14 Jun 2026",
    "dump_path": "/cases/evidence/dump.raw",
    "analyst_name": "John Doe",
    "status": "ready",
    "created_at": "2026-06-14T10:00:00Z"
  },
  "error": null
}
```

---

### GET `/api/cases`
Ambil semua case yang pernah dibuat.

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "case_id": "case_20260614_001",
      "case_name": "Insiden Server BSSN - 14 Jun 2026",
      "status": "completed",
      "created_at": "2026-06-14T10:00:00Z"
    }
  ],
  "error": null
}
```

---

### GET `/api/cases/:case_id`
Ambil detail satu case beserta status analisis.

**Response:**
```json
{
  "success": true,
  "data": {
    "case_id": "case_20260614_001",
    "case_name": "Insiden Server BSSN - 14 Jun 2026",
    "dump_path": "/cases/evidence/dump.raw",
    "analyst_name": "John Doe",
    "status": "completed",
    "created_at": "2026-06-14T10:00:00Z",
    "completed_at": "2026-06-14T10:15:00Z",
    "summary": {
      "total_processes": 87,
      "suspicious_processes": 3,
      "critical_alerts": 2,
      "high_alerts": 1,
      "ioc_found": 5,
      "yara_hits": 2
    }
  },
  "error": null
}
```

---

## 2. ANALYSIS — TRIGGER & STATUS

### POST `/api/cases/:case_id/analyze`
Trigger pipeline analisis penuh. Ini async — langsung return job_id, tidak nunggu selesai.

**Request Body:**
```json
{
  "plugins": ["windows.pslist", "windows.pstree", "windows.netscan", "windows.cmdline", "windows.malfind", "windows.dlllist"],
  "run_yara": true,
  "enrich_vt": true
}
```

**Response (langsung, tidak nunggu analisis selesai):**
```json
{
  "success": true,
  "data": {
    "job_id": "job_abc123",
    "case_id": "case_20260614_001",
    "status": "queued",
    "message": "Analisis dimulai. Pantau progress via WebSocket atau polling /status"
  },
  "error": null
}
```

---

### GET `/api/cases/{case_id}/status`
Polling status analisis. Frontend bisa hit endpoint ini tiap 3 detik.

**Response:**
```json
{
  "success": true,
  "data": {
    "job_id": "job_abc123",
    "case_id": "case_20260614_001",
    "status": "running",
    "progress": {
      "total_plugins": 6,
      "completed_plugins": 3,
      "current_plugin": "windows.malfind",
      "percent": 50
    }
  },
  "error": null
}
```

**Nilai `status` yang mungkin:**
- `queued` — antri, belum mulai
- `running` — sedang jalan
- `completed` — selesai
- `failed` — error

---

### WebSocket `ws://localhost:8000/ws/:case_id`
Alternatif polling — BE kirim update real-time ke FE.

**Message dari BE ke FE:**
```json
{
  "type": "progress",
  "plugin": "windows.malfind",
  "percent": 50,
  "status": "running"
}
```
```json
{
  "type": "completed",
  "percent": 100,
  "status": "completed"
}
```
```json
{
  "type": "error",
  "message": "Volatility3 gagal membaca dump file"
}
```

---

## 3. HASIL ANALISIS

### GET `/api/cases/:case_id/processes`
Ambil daftar semua proses hasil `windows.pslist` + `windows.pstree` + anomaly score.

**Response:**
```json
{
  "success": true,
  "data": {
    "processes": [
      {
        "pid": 4,
        "ppid": 0,
        "name": "System",
        "path": "N/A",
        "cmd": "",
        "create_time": "2026-06-14T08:00:00Z",
        "exit_time": null,
        "threads": 120,
        "handles": 2000,
        "wow64": false,
        "suspicion_score": 0,
        "suspicion_reasons": [],
        "severity": "clean"
      },
      {
        "pid": 5120,
        "ppid": 692,
        "name": "svchost.exe",
        "path": "C:\\Windows\\System32\\svchost.exe",
        "cmd": "svchost.exe -k netsvcs",
        "create_time": "2026-06-14T08:05:00Z",
        "exit_time": null,
        "threads": 12,
        "handles": 300,
        "wow64": false,
        "suspicion_score": 85,
        "suspicion_reasons": [
          "malfind_hit",
          "unusual_parent",
          "network_connection_to_malicious_ip"
        ],
        "severity": "critical"
      }
    ]
  },
  "error": null
}
```

**Nilai `severity`:**
- `clean` — score 0–30
- `low` — score 31–50
- `medium` — score 51–69
- `high` — score 70–84
- `critical` — score 85–100

---

### GET `/api/cases/:case_id/process-tree`
Ambil struktur pohon proses untuk visualisasi D3/vis-network.

**Response:**
```json
{
  "success": true,
  "data": {
    "nodes": [
      {
        "id": 4,
        "label": "System",
        "pid": 4,
        "ppid": 0,
        "severity": "clean",
        "suspicion_score": 0
      },
      {
        "id": 5120,
        "label": "svchost.exe",
        "pid": 5120,
        "ppid": 692,
        "severity": "critical",
        "suspicion_score": 85
      }
    ],
    "edges": [
      {
        "from": 4,
        "to": 692
      },
      {
        "from": 692,
        "to": 5120
      }
    ]
  },
  "error": null
}
```

> **Note untuk FE:** Format `nodes` dan `edges` ini sudah kompatibel langsung dengan vis-network.js. Tinggal di-pass langsung ke `new Network(container, data, options)`.

---

### GET `/api/cases/:case_id/network`
Ambil hasil `windows.netscan` — semua koneksi jaringan aktif.

**Response:**
```json
{
  "success": true,
  "data": {
    "connections": [
      {
        "pid": 5120,
        "process_name": "svchost.exe",
        "proto": "TCPv4",
        "local_addr": "192.168.1.10",
        "local_port": 49800,
        "foreign_addr": "185.220.101.45",
        "foreign_port": 443,
        "state": "ESTABLISHED",
        "create_time": "2026-06-14T09:30:00Z",
        "is_malicious": true,
        "vt_result": {
          "malicious_count": 42,
          "total_engines": 94,
          "malware_family": "CobaltStrike"
        },
        "geo": {
          "country": "Russia",
          "city": "Moscow",
          "lat": 55.7558,
          "lon": 37.6173
        }
      }
    ]
  },
  "error": null
}
```

---

### GET `/api/cases/:case_id/malfind`
Ambil hasil `windows.malfind` — memory region mencurigakan.

**Response:**
```json
{
  "success": true,
  "data": {
    "findings": [
      {
        "pid": 5120,
        "process_name": "svchost.exe",
        "address": "0x1f0000",
        "vad_tag": "VadS",
        "protection": "PAGE_EXECUTE_READWRITE",
        "disasm_preview": "4d 5a 90 00 03 00 00 00...",
        "has_pe_header": true,
        "severity": "critical"
      }
    ]
  },
  "error": null
}
```

---

### GET `/api/cases/:case_id/yara`
Ambil hasil YARA scan.

**Response:**
```json
{
  "success": true,
  "data": {
    "hits": [
      {
        "rule_name": "CobaltStrike_Beacon",
        "rule_file": "cobalt_strike.yar",
        "malware_family": "CobaltStrike",
        "pid": 5120,
        "process_name": "svchost.exe",
        "offset": "0x1f0000",
        "severity": "critical"
      }
    ]
  },
  "error": null
}
```

---

### GET `/api/cases/:case_id/iocs`
Ambil semua IOC yang ditemukan beserta enrichment VirusTotal.

**Response:**
```json
{
  "success": true,
  "data": {
    "iocs": [
      {
        "type": "ip",
        "value": "185.220.101.45",
        "found_in": ["windows.netscan"],
        "is_malicious": true,
        "vt_result": {
          "malicious_count": 42,
          "total_engines": 94,
          "malware_family": "CobaltStrike",
          "vt_link": "https://virustotal.com/gui/ip-address/185.220.101.45"
        },
        "geo": {
          "country": "Russia",
          "city": "Moscow"
        }
      },
      {
        "type": "domain",
        "value": "update.microsoft-cdn.ru",
        "found_in": ["strings"],
        "is_malicious": true,
        "vt_result": {
          "malicious_count": 31,
          "total_engines": 94,
          "malware_family": "CobaltStrike",
          "vt_link": "https://virustotal.com/gui/domain/update.microsoft-cdn.ru"
        }
      }
    ]
  },
  "error": null
}
```

---

### GET `/api/cases/:case_id/artifacts`
Ambil hasil custom plugin — artifact extractor (notepad, clipboard, dll).

**Response:**
```json
{
  "success": true,
  "data": {
    "artifacts": [
      {
        "type": "notepad",
        "plugin": "custom.notepad_extractor",
        "pid": 3024,
        "process_name": "notepad.exe",
        "content": "password: Sup3rS3cr3t!\nserver: 192.168.1.254",
        "recovered_at": "2026-06-14T10:10:00Z"
      },
      {
        "type": "clipboard",
        "plugin": "windows.clipboard",
        "content": "cmd.exe /c powershell -enc base64encodedpayload...",
        "recovered_at": "2026-06-14T10:10:00Z"
      }
    ]
  },
  "error": null
}
```

---

## 4. REPORT

### POST `/api/cases/:case_id/report`
Generate laporan triage. Async — return job_id.

**Request Body:**
```json
{
  "format": "pdf",
  "include_sections": ["summary", "processes", "network", "iocs", "yara", "artifacts", "recommendations"]
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "report_job_id": "report_xyz789",
    "status": "generating",
    "message": "Laporan sedang dibuat..."
  },
  "error": null
}
```

---

### GET `/api/cases/:case_id/report/download`
Download file laporan yang sudah selesai di-generate.

**Response:** File PDF/HTML (binary download)

> **Note untuk FE:** Buka URL ini di tab baru atau gunakan `<a href="..." download>` — jangan fetch manual karena response-nya binary.

---

## 5. UPLOAD (Opsional — untuk file kecil < 500MB)

### POST `/api/upload`
Upload dump file langsung via browser. Untuk file besar, gunakan local path di `/api/cases` saja.

**Request:** `multipart/form-data` dengan field `file`

**Response:**
```json
{
  "success": true,
  "data": {
    "saved_path": "/cases/uploads/dump_20260614_123456.raw",
    "filename": "dump.raw",
    "size_bytes": 2147483648
  },
  "error": null
}
```

---

## Catatan Penting untuk Tim

### Untuk Frontend (React)
- Semua tanggal dalam format **ISO 8601** (`2026-06-14T10:00:00Z`) — parse dengan `new Date()`
- Analisis bersifat **async** — jangan nunggu response, pakai polling `/status` tiap 3 detik atau WebSocket
- Format `nodes` + `edges` di `/process-tree` sudah siap pakai untuk **vis-network.js**
- Untuk severity color mapping:
  ```js
  const severityColor = {
    clean:    "#00ff88",
    low:      "#60a5fa",
    medium:   "#f5a623",
    high:     "#ff8c00",
    critical: "#ff4d5a"
  }
  ```

### Untuk Backend (FastAPI)
- Semua endpoint analisis harus **async** — gunakan Celery untuk task Vol3 yang lama
- Plugin Vol3 dijalankan dengan flag `--output=json` lalu `json.loads()`
- Simpan hasil tiap plugin ke SQLite atau file JSON per `case_id`
- VirusTotal API: rate limit 4 request/menit untuk free tier — implement queue + delay
- YARA scan bisa lama untuk dump besar — jalankan di Celery worker terpisah

### Shared Constants
```js
// status values
const STATUS = {
  QUEUED:    "queued",
  RUNNING:   "running",
  COMPLETED: "completed",
  FAILED:    "failed"
}

// severity values
const SEVERITY = {
  CLEAN:    "clean",     // score 0-30
  LOW:      "low",       // score 31-50
  MEDIUM:   "medium",    // score 51-69
  HIGH:     "high",      // score 70-84
  CRITICAL: "critical"   // score 85-100
}
```