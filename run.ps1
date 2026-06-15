# Script untuk menjalankan backend FastAPI Imprint

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Memulai Server Imprint (FastAPI)       " -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Coba dapatkan IP lokal untuk akses LAN
$localIp = (Get-NetIPAddress -AddressFamily IPv4 -PrefixOrigin Dhcp -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress
if (-not $localIp) {
    $localIp = "127.0.0.1"
}

Write-Host "🚀 Server sedang berjalan. Silakan klik link berikut (Ctrl + Click di VS Code):" -ForegroundColor Yellow
Write-Host ""
Write-Host "🔹 Frontend (Local) : " -NoNewline; Write-Host "http://localhost:3000/inprint" -ForegroundColor Blue
Write-Host "🔹 Frontend (LAN)   : " -NoNewline; Write-Host "http://$localIp:3000/inprint" -ForegroundColor Blue
Write-Host "🔹 API Endpoint     : " -NoNewline; Write-Host "http://localhost:3000/api/data" -ForegroundColor Blue
Write-Host "🔹 API Docs         : " -NoNewline; Write-Host "http://localhost:3000/docs" -ForegroundColor Blue
Write-Host ""
Write-Host "Gunakan CTRL+C untuk menghentikan server." -ForegroundColor Red
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Aktifkan virtual environment jika ada
if (Test-Path ".\venv\Scripts\Activate.ps1") {
    . ".\venv\Scripts\Activate.ps1"
} elseif (Test-Path ".\.venv\Scripts\Activate.ps1") {
    . ".\.venv\Scripts\Activate.ps1"
} else {
    Write-Host "Peringatan: Virtual environment tidak ditemukan di .\venv atau .\.venv" -ForegroundColor Red
}

# Jalankan server
python backend/app.py
