# ⚡ APKLens JADX Decompiler Backend

Autonomous, lightweight, containerized JADX reverse engineering service for **APKLens**.

Enables decompilation of Dalvik bytecode (`classes.dex` / `.apk`) into readable Java/Kotlin source code directly from the APKLens web dashboard.

---

## 🚀 Deploy to Render.com (100% Free)

You can run this backend service completely free on Render using Docker:

1. Log in to [Render Dashboard](https://dashboard.render.com/).
2. Click **"New +"** and select **"Web Service"**.
3. Connect your repository: `https://github.com/jojin1709/APKlens-`.
4. Configure the settings:
   - **Name:** `apklens-backend` *(or any unique name)*
   - **Language / Runtime:** `Docker`
   - **Branch:** `main`
   - **Root Directory:** `backend`
   - **Region:** Any (e.g. `Oregon (US West)` or `Frankfurt`)
   - **Instance Type:** **Free ($0 / month)**
   - **Health Check Path:** `/health`
5. Click **"Deploy Web Service"**.
6. Once deployed, Render gives you a URL (e.g., `https://apklens-backend.onrender.com`).
7. Open **APKLens** (`https://apklens-in.vercel.app/`), go to the **DEX / Code** tab, click **"Connect JADX Backend"**, and paste your Render URL!

---

## 💻 Run Locally with Docker

```bash
cd backend
docker build -t apklens-backend .
docker run -p 8000:8000 apklens-backend
```

Service is available at `http://localhost:8000`.

---

## 🔌 API Endpoints

- `GET /health` : Service health & JADX CLI version.
- `POST /api/decompile-class` : Uploads an APK/DEX + `className`, returns decompiled `.java` source code.
- `POST /api/decompile` : Batch decompilation returning directory tree and file contents.
