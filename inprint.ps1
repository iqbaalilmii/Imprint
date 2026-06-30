# inprint.ps1
$scriptPath = $PSScriptRoot
if ($scriptPath) { Set-Location $scriptPath }

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Memulai Server Imprint (FastAPI)       " -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$pythonExists = Get-Command "python" -ErrorAction SilentlyContinue
if (-not $pythonExists) {
    Write-Host "❌ Python global tidak ditemukan di sistem ini!" -ForegroundColor Red
    Write-Host "Harap install Python terlebih dahulu dari https://www.python.org/downloads/" -ForegroundColor Yellow
    Exit
}

$venvPython = ".\venv\Scripts\python.exe"
$venvPip = ".\venv\Scripts\pip.exe"

# Setup Otomatis tanpa menggunakan Activate.ps1 (menghindari error PSSecurityException)
if (-not (Test-Path $venvPython)) {
    Write-Host "🔧 Virtual Environment belum ditemukan. Menyiapkan sistem untuk pertama kali..." -ForegroundColor Yellow
    Write-Host "Membuat venv..." -ForegroundColor Gray
    python -m venv venv
    
    if (-not (Test-Path $venvPython)) {
        Write-Host "❌ Gagal membuat virtual environment." -ForegroundColor Red
        Exit
    }
    
    Write-Host "📦 Menginstall dependencies (FastAPI, Uvicorn)..." -ForegroundColor Gray
    & $venvPip install fastapi uvicorn
    Write-Host "✔️ Setup selesai!" -ForegroundColor Green
}

# Coba dapatkan IP lokal untuk akses LAN
$localIp = (Get-NetIPAddress -AddressFamily IPv4 -PrefixOrigin Dhcp -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress
if (-not $localIp) {
    $localIp = "127.0.0.1"
}

Write-Host ""
Write-Host "🚀 Server sedang berjalan. Silakan klik link berikut (Ctrl + Click di VS Code):" -ForegroundColor Yellow
Write-Host ""
Write-Host "🔹 Frontend (Local) : " -NoNewline; Write-Host "http://localhost:3000/inprint" -ForegroundColor Blue
Write-Host "🔹 Frontend (LAN)   : " -NoNewline; Write-Host "http://$($localIp):3000/inprint" -ForegroundColor Blue
Write-Host "🔹 API Endpoint     : " -NoNewline; Write-Host "http://localhost:3000/api/data" -ForegroundColor Blue
Write-Host "🔹 API Docs         : " -NoNewline; Write-Host "http://localhost:3000/docs" -ForegroundColor Blue
Write-Host ""
Write-Host "Gunakan CTRL+C pada keyboard (sebanyak 2 kali) untuk menghentikan server dan menutup." -ForegroundColor Red
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Jalankan server menggunakan Python secara langsung dari dalam VENV
& $venvPython backend/src/app.py
