import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, File, Form, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

app = FastAPI(title="APKLens JADX Decompiler API", version="2.0.0")

# Enable CORS for APKLens web app on Vercel & localhost
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {
        "service": "APKLens JADX Engine",
        "version": "2.0.0",
        "status": "online",
        "docs": "/docs",
        "health": "/health"
    }

@app.get("/health")
def health_check():
    jadx_version = "unknown"
    try:
        res = subprocess.run(["jadx", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        jadx_version = res.stdout.strip()
    except Exception as e:
        jadx_version = f"Error: {e}"

    return {
        "status": "healthy",
        "service": "APKLens JADX Engine",
        "jadx": jadx_version,
    }

@app.get("/api/decompile-class")
def decompile_class_info():
    return {
        "status": "ready",
        "service": "APKLens JADX Engine",
        "usage": "Send a POST request with multipart/form-data containing 'file' and 'className'"
    }

@app.post("/api/decompile-class")
async def decompile_class(
    file: UploadFile = File(...),
    className: str = Form(...),
):
    """
    Decompile a single target class from uploaded classes.dex or .apk file.
    Ultra-fast single-threaded compilation with memory bounds.
    """
    temp_dir = tempfile.mkdtemp(prefix="apklens_jadx_")
    try:
        # Normalize class name: e.g. "Lcom/android/insecurebankv2/PostLogin;" -> "com.android.insecurebankv2.PostLogin"
        clean_class = className.strip().lstrip("L").rstrip(";").replace("/", ".")
        input_filename = file.filename or "classes.dex"
        input_path = os.path.join(temp_dir, input_filename)
        
        with open(input_path, "wb") as f:
            shutil.copyfileobj(file.file, f)

        target_file = os.path.join(temp_dir, "decompiled.java")
        
        # Primary strategy: direct single-class extraction to target file
        cmd = [
            "jadx",
            "--no-res",
            "--no-imports",
            "-j", "1",
            "--single-class", clean_class,
            "--single-class-output", target_file,
            input_path
        ]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=50)

        found_code = None
        if os.path.exists(target_file) and os.path.getsize(target_file) > 0:
            with open(target_file, "r", encoding="utf-8", errors="replace") as f:
                found_code = f.read()

        # Secondary strategy: single-class into isolated directory
        if not found_code:
            out_dir = os.path.join(temp_dir, "out")
            os.makedirs(out_dir, exist_ok=True)
            cmd2 = [
                "jadx",
                "--no-res",
                "-j", "1",
                "--single-class", clean_class,
                "-d", out_dir,
                input_path
            ]
            res = subprocess.run(cmd2, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=50)

            sources_dir = os.path.join(out_dir, "sources")
            target_basename = clean_class.split(".")[-1] + ".java"
            if os.path.exists(sources_dir):
                for root, _, files in os.walk(sources_dir):
                    if target_basename in files:
                        with open(os.path.join(root, target_basename), "r", encoding="utf-8", errors="replace") as f:
                            found_code = f.read()
                            break

        if not found_code:
            return JSONResponse(
                status_code=404,
                content={
                    "error": f"Class '{clean_class}' could not be decompiled or was not found in the uploaded binary.",
                    "jadx_stdout": res.stdout,
                    "jadx_stderr": res.stderr
                }
            )

        return {
            "className": clean_class,
            "code": found_code,
            "status": "success"
        }

    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Decompilation timed out under container resource constraints.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

@app.post("/api/decompile")
async def decompile_all(
    file: UploadFile = File(...),
    maxFiles: Optional[int] = Form(50),
):
    """
    Decompile classes.dex or APK and return directory tree with source code up to maxFiles.
    """
    temp_dir = tempfile.mkdtemp(prefix="apklens_all_")
    try:
        input_filename = file.filename or "classes.dex"
        input_path = os.path.join(temp_dir, input_filename)
        with open(input_path, "wb") as f:
            shutil.copyfileobj(file.file, f)

        out_dir = os.path.join(temp_dir, "decompiled")
        os.makedirs(out_dir, exist_ok=True)

        cmd = ["jadx", "--no-res", "-j", "1", "-d", out_dir, input_path]
        subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=90)

        sources_dir = os.path.join(out_dir, "sources")
        decompiled_files = []

        if os.path.exists(sources_dir):
            for root, _, files in os.walk(sources_dir):
                for f in files:
                    if f.endswith(".java") or f.endswith(".kt"):
                        full_path = os.path.join(root, f)
                        rel_path = os.path.relpath(full_path, sources_dir).replace("\\", "/")
                        with open(full_path, "r", encoding="utf-8", errors="replace") as content_file:
                            code_snippet = content_file.read()
                        decompiled_files.append({
                            "path": rel_path,
                            "name": f,
                            "code": code_snippet,
                            "size": len(code_snippet)
                        })
                        if len(decompiled_files) >= (maxFiles or 50):
                            break
                if len(decompiled_files) >= (maxFiles or 50):
                    break

        return {
            "status": "success",
            "totalDecompiled": len(decompiled_files),
            "files": decompiled_files
        }

    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Decompilation timed out.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
