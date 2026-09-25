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

import hashlib

CACHE_DIR = Path("/tmp/apklens_cache")
try:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
except Exception:
    pass

class_cache: dict[str, str] = {}

@app.post("/api/decompile-class")
async def decompile_class(
    file: Optional[UploadFile] = File(None),
    fileHash: Optional[str] = Form(None),
    className: str = Form(...),
):
    """
    Decompile a single target class from uploaded .apk or classes.dex file.
    Ultra-optimized single-class compilation with C1 JIT, disk blob caching, and memory bounds.
    """
    # Normalize class name: e.g. "Lcom/android/insecurebankv2/PostLogin;" -> "com.android.insecurebankv2.PostLogin"
    clean_class = className.strip().lstrip("L").rstrip(";").replace("/", ".")

    target_apk_path = None
    target_hash = fileHash.strip() if fileHash else None

    # Check if binary is already cached on disk by fileHash
    if target_hash:
        cached_file_path = CACHE_DIR / f"{target_hash}.bin"
        if cached_file_path.exists() and cached_file_path.stat().st_size > 0:
            target_apk_path = str(cached_file_path)

    temp_created_path = None
    # If not on disk by hash, read uploaded file
    if not target_apk_path:
        if not file:
            raise HTTPException(
                status_code=400,
                detail="Binary source file not found on server. Please include the 'file' payload."
            )
        file_bytes = await file.read()
        if not file_bytes:
            raise HTTPException(status_code=400, detail="Empty file payload received.")

        computed_hash = hashlib.sha256(file_bytes).hexdigest()
        target_hash = target_hash or computed_hash
        cached_file_path = CACHE_DIR / f"{target_hash}.bin"

        try:
            with open(cached_file_path, "wb") as f:
                f.write(file_bytes)
            target_apk_path = str(cached_file_path)
        except Exception:
            # Fallback to temp file if cache dir write fails
            temp_f = tempfile.NamedTemporaryFile(delete=False, suffix=".apk")
            temp_f.write(file_bytes)
            temp_f.close()
            target_apk_path = temp_f.name
            temp_created_path = target_apk_path

    # Check memory cache for already decompiled class
    cache_key = f"{target_hash}:{clean_class}"
    if cache_key in class_cache:
        return {
            "className": clean_class,
            "code": class_cache[cache_key],
            "status": "cached"
        }

    temp_dir = tempfile.mkdtemp(prefix="apklens_jadx_")
    try:
        target_file = os.path.join(temp_dir, "decompiled.java")

        # C1 compiler mode for lightning-fast startup and minimal RAM footprint
        jadx_env = os.environ.copy()
        jadx_env["JAVA_OPTS"] = "-Xms64m -Xmx320m -XX:+UseSerialGC -XX:TieredStopAtLevel=1 -XX:CICompilerCount=1"

        # Primary strategy: direct single-class extraction with high-speed flags
        cmd = [
            "jadx",
            "--no-res",
            "--no-imports",
            "--show-bad-code",
            "--no-inline-anonymous",
            "--no-inline-methods",
            "--comments-level", "none",
            "-j", "2",
            "--single-class", clean_class,
            "--single-class-output", target_file,
            target_apk_path
        ]
        res = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=85,
            env=jadx_env
        )

        found_code = None
        if os.path.exists(target_file) and os.path.getsize(target_file) > 0:
            with open(target_file, "r", encoding="utf-8", errors="replace") as f:
                found_code = f.read()

        # Secondary strategy: isolated directory with fallback mode
        if not found_code:
            out_dir = os.path.join(temp_dir, "out")
            os.makedirs(out_dir, exist_ok=True)
            cmd2 = [
                "jadx",
                "--no-res",
                "--no-imports",
                "--show-bad-code",
                "--fallback",
                "-j", "2",
                "--single-class", clean_class,
                "-d", out_dir,
                target_apk_path
            ]
            res = subprocess.run(
                cmd2,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=45,
                env=jadx_env
            )

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

        # Store in cache (limit to 500 items)
        if len(class_cache) > 500:
            class_cache.clear()
        class_cache[cache_key] = found_code

        return {
            "className": clean_class,
            "code": found_code,
            "status": "success",
            "cached": False
        }

    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=504,
            detail="Decompilation timed out under container resource constraints. Please retry with a specific application class."
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
        if temp_created_path and os.path.exists(temp_created_path):
            try:
                os.remove(temp_created_path)
            except Exception:
                pass

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
