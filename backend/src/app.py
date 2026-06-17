import uvicorn
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
import os

# Membuat instance FastAPI
app = FastAPI()

# Menambahkan middleware untuk CORS (Cross-Origin Resource Sharing)
# Ini memungkinkan frontend (yang berjalan di domain berbeda jika dibuka sebagai file)
# untuk berkomunikasi dengan backend.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Mengizinkan semua origin
    allow_credentials=True,
    allow_methods=["*"],  # Mengizinkan Pisemua metode (GET, POST, dll.)
    allow_headers=["*"],  # Mengizinkan semua header
)

# Mendapatkan path absolut ke direktori frontend
# Ini penting agar path file benar di sistem operasi manapun.
frontend_dir = os.path.join(os.path.dirname(__file__), "..", "frontend")
# Logika untuk menentukan folder frontend (Script vs Frozen EXE)
if getattr(sys, 'frozen', False):
    # Jika berjalan di dalam PyInstaller EXE
    base_path = sys._MEIPASS
    frontend_dir = os.path.join(base_path, "frontend", "dist")
else:
    # Jika berjalan sebagai script Python biasa
    base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    frontend_dir = os.path.join(base_path, "..", "frontend", "dist")

index_html_path = os.path.join(frontend_dir, "index.html")

@app.get("/inprint")
async def read_index():
    """
    Endpoint ini akan menyajikan file index.html dari folder frontend.
    """
    return FileResponse(index_html_path)

@app.get("/api/data")
async def get_data():
    """
    Endpoint API sederhana yang mengembalikan data JSON.
    """
    return {"message": "Halo dari Backend FastAPI!", "project": "Proyek Keren"}
# --- API Berdasarkan Kontrak ---

@app.post("/api/cases")
async def create_case(case_data: dict):
    # Placeholder untuk logika pendaftaran case
    return {
        "success": True,
        "data": {
            "case_id": "case_test_001",
            "status": "ready"
        },
        "error": null
    }

@app.get("/api/cases/{case_id}/status")
async def get_case_status(case_id: str):
    return {
        "success": True,
        "data": {"status": "running", "progress": {"percent": 45}}
    }

# Mounting Static Files (CSS, JS dari Vite)
# Harus diletakkan setelah definisi route lain agar tidak menimpa /api
if os.path.exists(frontend_dir):
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="static")

if __name__ == "__main__":
    # Menjalankan server menggunakan uvicorn di localhost pada port 3000
    # Port disesuaikan ke 3000 seperti yang ada di script inprint.ps1
    uvicorn.run(app, host="0.0.0.0", port=3000)
