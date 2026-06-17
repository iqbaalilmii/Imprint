# 🧠 Engram

> **Automated Volatile Memory Forensics Platform** > Developed by Team: **"Bastion Seize"** ·

---

## 📌 Sekilas Tentang Engram

**Engram** adalah platform forensik memori (*volatile memory forensics*) modern yang mendeteksi, menganalisis, dan memvisualisasikan *RAM dump* secara otomatis untuk keperluan investigasi insiden (*Incident Response*). 

Terinspirasi dari alur kerja *Autopsy Forensic Browser*, **Engram** membawa kekuatan analisis memori tingkat dalam ke dalam antarmuka web yang intuitif. Cukup unggah *memory dump*, jalankan satu perintah, dan biarkan pipeline otomatis kami membedah memori di latar belakang sementara Anda menganalisis hasilnya langsung dari browser di `localhost`.

---

## 💥 Latar Belakang & Masalah

Serangan siber modern — terutama dalam operasi *Cyber Warfare* tingkat tinggi — semakin bergantung pada teknik **Fileless Malware**. Ini adalah jenis malware yang hanya hidup di dalam RAM dan tidak meninggalkan jejak fisik di dalam *harddisk* (*disk*). 

Beberapa teknik manipulasi memori evasif yang sering digunakan meliputi:
* **Process Injection**: Menyuntikkan kode jahat ke dalam proses Windows yang sah (e.g., `rundll32.exe`).
* **Process Hollowing**: Mengosongkan memori proses legitim dan menggantinya dengan payload berbahaya.
* **Reflective DLL Injection**: Memuat file DLL malware langsung ke memori tanpa menyentuh *disk*.
* **Living-off-the-Land (LotL)**: Menyalahgunakan *tools* bawaan sistem operasi seperti PowerShell untuk mengeksekusi perintah jahat.

**Masalahnya:** *Antivirus* konvensional tidak mampu mendeteksi aktivitas ini karena mereka hanya memindai *disk*. Alat standar industri seperti **Volatility 3** sangat kuat, tetapi murni berbasis CLI (Command Line) dan membutuhkan keahlian teknis yang sangat tinggi. Proses korelasi data manual antara daftar proses, koneksi jaringan, dan injeksi memori bisa memakan waktu berjam-jam.

**Solusi Kami:** **Engram** mengotomatisasi seluruh pipeline forensik ini. Kami memangkas waktu investigasi dari hitungan jam menjadi menit, memberikan visualisasi korelasi data instan bagi tim analis SOC dan *Incident Responder*.

---

## 🛠️ Arsitektur Teknologi

Engram dibangun dengan arsitektur client-server yang berjalan sepenuhnya di lingkungan lokal pengguna untuk memastikan keamanan dan kecepatan data.

*   **Backend Engine (Python & FastAPI):**
    *   **Teknologi:** Menggunakan framework **FastAPI** dari Python.
    *   **Peran:** Bertindak sebagai "mesin" utama yang berjalan di `localhost`. Backend ini menangani semua pemrosesan berat: menerima unggahan file *RAM dump*, menjalankan modul **Volatility 3** secara *asynchronous* di latar belakang, mem-parsing output data mentah (teks/JSON), dan mengintegrasikannya dengan *OSINT Threat Intelligence* (seperti VirusTotal).

*   **Frontend UI (React.js):**
    *   **Teknologi:** Dibangun sebagai *Single-Page Application* (SPA) menggunakan **React.js** dan di-styling dengan **Tailwind CSS**.
    *   **Peran:** Menyajikan antarmuka pengguna (UI) berupa dasbor interaktif ala *Security Operations Center* (SOC) yang diakses melalui browser. Frontend berkomunikasi dengan backend FastAPI untuk menampilkan hasil analisis secara visual, responsif, dan mudah dipahami untuk melacak relasi PID, status memori jahat, dan indikator kompromi (IOC).

*   **Forensics Engine:**
    *   **Teknologi:** Integrasi langsung dengan **Volatility 3 Framework**.
    *   **Peran:** Merupakan alat inti yang digunakan untuk melakukan ekstraksi dan analisis artefak dari memori dump.

---

## 🚀 Fitur Utama (Core Panels)

1. **Process List Tracker**: Menganalisis pohon proses (`pslist`/`pstree`), melacak Parent PID (PPID), dan otomatis memberikan tanda merah jika ada proses fileless tanpa path file yang jelas di disk.
2. **Network Connections Monitor**: Memetakan sisa-sisa struktur data jaringan (`netscan`) untuk mencocokkan PID lokal dengan IP/Domain asing (mendeteksi aktivitas *C2 Beaconing*).
3. **Malfind Analyzer**: Menyisir memori VAD (*Virtual Address Descriptor*) untuk memburu proteksi memori mencurigakan seperti `PAGE_EXECUTE_READWRITE` (RWX).
4. **IOC Automated List**: Ekstraksi otomatis indikator kompromi (IP, Domain, dan Hash) dibarengi dengan skor reputasi intelijen ancaman.

---
