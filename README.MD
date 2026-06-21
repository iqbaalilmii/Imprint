# Engram

**Automated Volatile Memory Forensics Platform**
Dibuat oleh Team **Bastion Seize**

![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat-square&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=flat-square&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react&logoColor=black)
![Tailwind](https://img.shields.io/badge/TailwindCSS-3.x-06B6D4?style=flat-square&logo=tailwindcss&logoColor=white)
![Volatility](https://img.shields.io/badge/Volatility-3-CC0000?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-22C55E?style=flat-square)

---

Engram adalah platform forensik memori yang membungkus Volatility 3 ke dalam pipeline otomatis dengan dashboard web. Masukin path memory dump, biarin pipeline-nya jalan, dan hasilnya langsung muncul di browser sebagai proses tree, network connections, malfind findings, dan IOC list yang udah di-enrich pakai VirusTotal.

Jalan sepenuhnya di localhost. Tidak ada dump file atau hasil analisis yang keluar dari mesin, kecuali request enrichment ke VirusTotal API.

## Demo

<p align="center">
  <img src="https://github.com/user-attachments/assets/7ed41447-3050-4952-a4ff-d65c3c25d25c" alt="Engram - Cases Dashboard" width="100%" />
  <br/><em>Cases Dashboard</em>
</p>

<p align="center">
  <img src="https://github.com/user-attachments/assets/22eb4bd6-9bd1-4814-a256-8501625c7979" alt="Engram - Analysis Panel" width="100%" />
  <br/><em>Analysis Panel</em>
</p>

<p align="center">
  <img src="https://github.com/user-attachments/assets/0004bd91-7534-4044-9f9c-4f26d279fd8c" alt="Engram - IOC & Threat Intel" width="100%" />
  <br/><em>IOC List dengan skor VirusTotal</em>
</p>

## Kenapa ini dibuat

Volatility 3 itu solid, tapi murni CLI. Tiap kali handle case, alurnya selalu sama: jalanin `pslist`, catat hasilnya, jalanin `pstree`, copy-paste ke notes, jalanin `netscan`, cocokin manual sama IP yang dicurigai, lanjut `malfind`, baca hex dump satu-satu. Untuk yang udah biasa, ini makan waktu. Untuk analyst L1 atau yang baru masuk SOC, learning curve-nya curam — belum lagi kalau harus eskalasi ke senior analyst yang juga sibuk.

Masalahnya makin kerasa kalau lawan yang dihadapi pakai fileless malware. Teknik kayak process injection, process hollowing, reflective DLL injection, sampe living-off-the-land lewat PowerShell — semuanya tidak nyentuh disk, jadi antivirus konvensional yang cuma scan filesystem ya jelas nggak nangkep apa-apa. Satu-satunya jejak yang ketinggalan ada di RAM, dan begitu mesin dimatikan, itu hilang.

Angkanya juga nggak enak didengar. SentinelOne nyebut sekitar 70% serangan malware serius sekarang pakai teknik fileless, dan menurut HackingLoops jumlah ini naik 78% dalam setahun terakhir. PurpleSec mencatat 77% ransomware yang berhasil tembus itu lolos lewat teknik fileless. Sementara itu Mandiant M-Trends nyebut ada kasus di mana eksfiltrasi data kelar dalam kurang dari satu jam — dan kalau proses investigasi manual aja udah makan 2 jam per case (data dari SOC Operations Survey di arxiv), ya keduluan terus.

Engram nggak nyoba gantiin Volatility — itu tetap jadi engine-nya. Yang dipangkas adalah waktu antara "dump file siap" sampai "ketemu indikasi serangan". Targetnya dari hitungan jam jadi hitungan menit, dan hasilnya udah dikorelasi otomatis biar nggak perlu loncat-loncat terminal.

## Prerequisites

| Kebutuhan | Keterangan |
|-----------|------------|
| Docker & Docker Compose | cara paling gampang buat jalanin ini |
| Python 3.11+ | kalau mau jalan tanpa Docker |
| Node.js 18+ | kalau mau jalan tanpa Docker |
| Memory dump | format `.raw`, `.mem`, `.vmem`, atau `.dmp` |
| VirusTotal API key | [daftar gratis di sini](https://www.virustotal.com/gui/join-us) |
| RAM host minimal 8 GB | buat handle dump yang gede |

## Quick Start

### Pakai Docker (disaranin)

```bash
git clone https://github.com/bastion-seize/engram.git
cd engram

cp .env.example .env
# isi VIRUSTOTAL_API_KEY di .env

docker-compose up --build
```

Buka `http://localhost:3000` buat frontend, `http://localhost:8000/docs` buat API docs.

### Manual (tanpa Docker)

```bash
# backend
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# frontend, terminal baru
cd frontend
npm install
npm run dev
```

## Cara Pakai

1. Buka `http://localhost:3000`
2. Upload memory dump atau masukin path ke direktori tempat dump disimpan
3. Pipeline jalan otomatis di background — Volatility 3 dieksekusi plugin per plugin
4. Pantau hasilnya lewat 4 panel:

| Panel | Isinya |
|---|---|
| Process List Tracker | proses tree + flag anomali |
| Network Connections Monitor | koneksi aktif, kecocokan sama IOC |
| Malfind Analyzer | region memori dengan proteksi mencurigakan |
| IOC Automated List | IP/domain/hash yang diekstrak + skor VirusTotal |

## Arsitektur

```
┌─────────────────────────────────────────────┐
│                  Browser                    │
│           React.js + Tailwind CSS           │
└────────────────────┬────────────────────────┘
                     │ HTTP / REST API
┌────────────────────▼────────────────────────┐
│            Backend (FastAPI)                │
│   • Upload handler & job queue (async)      │
│   • Volatility 3 plugin runner              │
│   • Output parser (text → JSON)             │
│   • VirusTotal integration                  │
└──────────┬──────────────────────┬───────────┘
           │                      │
┌──────────▼──────────┐  ┌───────▼──────────┐
│    Volatility 3     │  │   VirusTotal API  │
└─────────────────────┘  └──────────────────┘
```

| Layer | Tech | Peran |
|---|---|---|
| Frontend | React, Tailwind CSS | dashboard |
| Backend | Python, FastAPI | orchestrate pipeline |
| Forensics engine | Volatility 3 | ekstraksi artefak memori |
| Threat intel | VirusTotal API | scoring reputasi IOC |

## Fitur Utama

**Process List Tracker** jalanin `pslist`/`pstree`, cocokin PPID, dan otomatis flag proses yang nggak punya path di disk. Itu indikator kuat ada process injection atau hollowing.

**Network Connections Monitor** baca hasil `netscan`, cocokin PID lokal sama IP/domain asing, kelar deteksi pattern C2 beaconing tanpa harus baca satu-satu manual.

**Malfind Analyzer** sisir VAD buat nemu region dengan proteksi `PAGE_EXECUTE_READWRITE`. Ini signature umum shellcode injection, tapi catat: plugin ini noisy, false positive itu normal.

**IOC Automated List** semua IP, domain, dan hash yang ketemu di seluruh hasil analisis dikumpulin dan langsung di-enrich pakai VirusTotal.

## Contoh Output

Dites pakai sample dump publik dari [MemLabs](https://github.com/stuxnet999/MemLabs):

```
File     : memdump.raw (4.2 GB)
OS Target: Windows 10 x64

Analisis selesai dalam ~4 menit 30 detik

Ringkasan:
  Proses mencurigakan      : 3
  Koneksi jaringan aktif    : 12 (2 flagged)
  Region memori RWX         : 7
  IOC diekstrak             : 5 IP, 2 domain, 3 hash
  VT hits                   : 2 IP berbahaya (45/72, 38/72)
```

Hasil aktual bakal beda-beda tergantung kondisi dump dan target sistemnya.

## Limitations

- Cuma support Windows memory dump untuk sekarang. Linux belum.
- Malfind itu noisy by design — review manual tetap perlu, jangan langsung percaya semua flag-nya.
- Dites stabil sampai dump ~8GB. Lebih besar dari itu, butuh resource tambahan dan belum dites secara konsisten.
- IOC scoring butuh koneksi internet buat hit VirusTotal API.
- VirusTotal free tier dibatasi 4 request/menit, jadi analisis IOC dalam jumlah besar bakal melambat di bagian ini.

## Lisensi

MIT. Lihat [`LICENSE`](LICENSE).

---

<div align="center">
  <sub>Built by Team Bastion Seize · Hackathon 2025</sub>
</div>
