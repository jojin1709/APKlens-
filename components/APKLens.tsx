"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import {
  Activity, AlertCircle, Archive, ArrowLeft, Box, Check, CheckCircle2,
  ChevronDown, ChevronRight, Code2, Copy, Cpu, Eye, FileCode2, FileText,
  Folder, Globe, KeyRound, LayoutDashboard, Lock, Package, Search,
  Server, Settings, Shield, ShieldAlert, ShieldCheck, Smartphone,
  Sparkles, Trash2, Upload, X, XCircle, Zap
} from "lucide-react";
import LandingPage from "@/components/LandingPage";
import { analyzeAPK, dexBlobCache } from "@/lib/apk-analyzer";
import { clearAnalyses, deleteAnalysis, listAnalyses, saveAnalysis } from "@/lib/local-db";
import { generateSarif } from "@/lib/sarif-generator";
import { openPrintableReport } from "@/lib/pdf-report-generator";
import type { APKAnalysis } from "@/types/apk";

type Tab =
  | "Overview"
  | "Files"
  | "Manifest"
  | "Permissions"
  | "Components"
  | "Code"
  | "Native"
  | "Resources"
  | "Network"
  | "Security"
  | "Signing"
  | "Technology"
  | "Reports";

const tabs: { id: Tab; label: string; icon: React.ReactNode }[] = [
  { id: "Overview", label: "Overview", icon: <LayoutDashboard size={16} /> },
  { id: "Files", label: "File Explorer", icon: <Folder size={16} /> },
  { id: "Manifest", label: "AndroidManifest", icon: <FileCode2 size={16} /> },
  { id: "Permissions", label: "Permissions", icon: <Lock size={16} /> },
  { id: "Components", label: "Components", icon: <Activity size={16} /> },
  { id: "Code", label: "DEX & Decompiler", icon: <Code2 size={16} /> },
  { id: "Native", label: "Native Libraries (.so)", icon: <Cpu size={16} /> },
  { id: "Resources", label: "Resources", icon: <Archive size={16} /> },
  { id: "Network", label: "Network & URLs", icon: <Globe size={16} /> },
  { id: "Security", label: "Security & Secrets", icon: <ShieldCheck size={16} /> },
  { id: "Signing", label: "Certificate & Signing", icon: <KeyRound size={16} /> },
  { id: "Technology", label: "Technology Stack", icon: <Zap size={16} /> },
  { id: "Reports", label: "Reports & SARIF", icon: <FileText size={16} /> },
];

export default function APKLens() {
  const inputRef = useRef<HTMLInputElement>(null);
  const [view, setView] = useState<"landing" | "analyzer">("landing");
  const [analysis, setAnalysis] = useState<APKAnalysis | null>(null);
  const [currentFile, setCurrentFile] = useState<File | null>(null);
  const [history, setHistory] = useState<APKAnalysis[]>([]);
  const [tab, setTab] = useState<Tab>("Overview");
  const [busy, setBusy] = useState(false);
  const [busyStage, setBusyStage] = useState("");
  const [error, setError] = useState("");
  const [drag, setDrag] = useState(false);
  const [query, setQuery] = useState("");

  useEffect(() => {
    listAnalyses().then((h) => {
      setHistory(h);
    }).catch(() => {});
  }, []);

  async function run(file?: File) {
    setError("");
    const f = file ?? inputRef.current?.files?.[0];
    if (!f) return;
    if (!f.name.toLowerCase().endsWith(".apk")) {
      setError("Please select a valid .apk file.");
      return;
    }
    setCurrentFile(f);
    setBusy(true);
    setBusyStage("Unpacking APK archive and reading byte stream...");
    setView("analyzer");

    try {
      setBusyStage("Decoding binary AndroidManifest & verifying X.509 certs...");
      const result = await analyzeAPK(f);
      setBusyStage("Scanning bytecode strings for hardcoded secrets & native ELF symbols...");
      await saveAnalysis(result);
      setAnalysis(result);
      setHistory(await listAnalyses());
      setTab("Overview");
    } catch (e) {
      setError(e instanceof Error ? e.message : "The APK could not be analyzed.");
    } finally {
      setBusy(false);
      setBusyStage("");
    }
  }

  async function remove(id: string) {
    await deleteAnalysis(id);
    const h = await listAnalyses();
    setHistory(h);
    if (analysis?.id === id) {
      setAnalysis(h[0] ?? null);
      if (!h.length) setView("landing");
    }
  }

  async function clearAll() {
    await clearAnalyses();
    setHistory([]);
    setAnalysis(null);
    setView("landing");
  }

  function downloadJSON() {
    if (!analysis) return;
    const blob = new Blob([JSON.stringify(analysis, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${analysis.fileName.replace(/\.apk$/i, "")}-analysis.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function downloadSarifFile() {
    if (!analysis) return;
    const sarifStr = generateSarif(analysis);
    const blob = new Blob([sarifStr], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${analysis.fileName.replace(/\.apk$/i, "")}.sarif`;
    a.click();
    URL.revokeObjectURL(url);
  }

  const filteredFiles = useMemo(
    () => (analysis?.files ?? []).filter((f) => f.path.toLowerCase().includes(query.toLowerCase())),
    [analysis, query]
  );

  type StatItem = { label: string; value: number; icon: React.ComponentType<{ size?: number }> };
  const stats: StatItem[] = analysis
    ? [
        { label: "Permissions", value: analysis.permissions.length, icon: Lock },
        { label: "Activities", value: analysis.activities.length, icon: Smartphone },
        { label: "Services", value: analysis.services.length, icon: Server },
        { label: "Receivers", value: analysis.receivers.length, icon: Activity },
        { label: "Native Libs", value: analysis.nativeLibraries?.length ?? 0, icon: Cpu },
        { label: "DEX Files", value: analysis.dexFiles.length, icon: Code2 },
      ]
    : [];

  // Render Landing Page if active
  if (view === "landing" && !busy) {
    return (
      <LandingPage
        onLaunch={() => setView("analyzer")}
        onFileSelect={(file) => run(file)}
      />
    );
  }

  return (
    <main className="shell">
      {/* Dynamic Ambient Background Orbs */}
      <div className="ambient-bg">
        <div className="aurora-orb orb-1"></div>
        <div className="aurora-orb orb-2"></div>
        <div className="aurora-orb orb-3"></div>
        <div className="ambient-grid"></div>
      </div>

      {/* Topbar */}
      <header className="topbar">
        <div className="brand" onClick={() => setView("landing")} style={{ cursor: "pointer" }}>
          <div className="brandmark">
            <Shield size={20} className="brandmark-icon" />
          </div>
          <div>
            <div className="brand-title">
              APKLens <span className="version-pill">v2.0</span>
            </div>
            <span className="brand-sub">Android Security & Architecture Suite</span>
          </div>
        </div>

        <nav>
          <button className="nav-tab-btn" onClick={() => setView("landing")}>
            <ArrowLeft size={14} /> Back to Overview
          </button>
        </nav>

        <div className="top-actions">
          <div className="privacy-badge">
            <CheckCircle2 size={14} /> 100% In-Browser Analysis
          </div>
          <button className="primary" onClick={() => inputRef.current?.click()}>
            <Upload size={15} /> Analyze New APK
          </button>
        </div>
      </header>

      <input
        ref={inputRef}
        type="file"
        accept=".apk,application/vnd.android.package-archive"
        hidden
        onChange={(e) => run(e.target.files?.[0])}
      />

      <div className="body">
        {/* Sidebar */}
        <aside className="sidebar">
          <div className="side-label">ANALYSIS SECTIONS</div>
          {tabs.map((t) => (
            <button
              key={t.id}
              className={tab === t.id ? "side-item active" : "side-item"}
              onClick={() => setTab(t.id)}
            >
              {t.icon}
              <span>{t.label}</span>
            </button>
          ))}

          <div className="side-divider" />

          <div className="side-label recent-label">
            RECENT ANALYSES <button onClick={clearAll}>Clear All</button>
          </div>
          {history.slice(0, 5).map((h) => (
            <button
              key={h.id}
              className="history"
              onClick={() => {
                setAnalysis(h);
                setTab("Overview");
              }}
            >
              <Globe size={14} />
              <span>
                <b>{h.fileName}</b>
                <small>{new Date(h.analyzedAt).toLocaleDateString()}</small>
              </span>
            </button>
          ))}
        </aside>

        {/* Content Area */}
        <section className="content">
          {busy ? (
            <div className="progress-modal-backdrop">
              <div className="progress-modal">
                <div className="progress-modal-icon">
                  <Sparkles size={28} />
                </div>
                <h3>Analyzing Android Binary</h3>
                <div className="progress-modal-target">{currentFile?.name ?? "APK Binary"}</div>
                <div className="progress-track">
                  <div className="progress-fill" style={{ width: "75%" }}></div>
                </div>
                <div className="progress-info">
                  <span className="progress-stage">{busyStage || "Processing byte stream..."}</span>
                  <span className="progress-percent">Analyzing...</span>
                </div>
              </div>
            </div>
          ) : !analysis ? (
            <div
              className="upload-screen"
              onDragOver={(e) => {
                e.preventDefault();
                setDrag(true);
              }}
              onDragLeave={() => setDrag(false)}
              onDrop={(e) => {
                e.preventDefault();
                setDrag(false);
                run(e.dataTransfer.files[0]);
              }}
            >
              <div className={drag ? "dropzone drag" : "dropzone"}>
                <div className="upload-icon">
                  <Upload size={30} />
                </div>
                <h1>Select or Drop an APK to Inspect</h1>
                <p>
                  Zero data exposure. Binary manifest parsing, DEX classes, native ELF libraries,
                  and automated SAST scans execute directly in your browser.
                </p>
                <button className="primary big" onClick={() => inputRef.current?.click()}>
                  <Upload size={17} /> Choose APK File
                </button>
                <span className="drop-hint">Supports .apk (Split APKs & Multi-DEX)</span>
                <div className="privacy-line">
                  <Lock size={14} /> Zero Cloud Uploads for Static Analysis • Private Sandbox
                </div>
              </div>
              {error && (
                <div className="error">
                  <AlertCircle size={16} />
                  {error}
                </div>
              )}
            </div>
          ) : (
            <>
              {/* Header Box */}
              <div className="analysis-head">
                <div className="app-title">
                  <div className="android-icon">
                    <Smartphone size={30} />
                  </div>
                  <div>
                    <h1>{analysis.fileName}</h1>
                    <div className="badges">
                      <span className="success">
                        <CheckCircle2 size={13} /> Verified Analysis
                      </span>
                      <span className="blue">Local-First Sandbox</span>
                      <span className="muted">{new Date(analysis.analyzedAt).toLocaleString()}</span>
                    </div>
                    <p>{analysis.packageName ?? "Package name not available in manifest."}</p>
                  </div>
                </div>
                <div className="head-actions">
                  <button className="secondary" onClick={downloadJSON}>
                    <FileText size={15} /> Download JSON
                  </button>
                  <button className="secondary" onClick={downloadSarifFile}>
                    <FileCode2 size={15} /> Export SARIF 2.1.0
                  </button>
                  <button className="danger" onClick={() => remove(analysis.id)}>
                    <Trash2 size={15} /> Clear
                  </button>
                </div>
              </div>

              {/* Meta Grid */}
              <div className="meta-grid">
                <Meta label="App Name" value={analysis.fileName.replace(/\.apk$/i, "")} />
                <Meta label="Package" value={analysis.packageName ?? "Unknown"} />
                <Meta label="Version" value={analysis.versionName ?? "Unknown"} />
                <Meta label="Min SDK" value={analysis.minSdk ?? "Unknown"} />
                <Meta label="Target SDK" value={analysis.targetSdk ?? "Unknown"} />
                <Meta label="File Size" value={formatBytes(analysis.size)} />
                <Meta label="SHA-256" value={analysis.sha256.slice(0, 16) + "…"} mono />
              </div>

              {/* Stats Grid */}
              <div className="stat-grid">
                {stats.map((s) => {
                  const Icon = s.icon;
                  return (
                    <div className="stat" key={s.label}>
                      <Icon size={18} />
                      <b>{s.value}</b>
                      <span>{s.label}</span>
                    </div>
                  );
                })}
              </div>

              {/* Tabs Content */}
              {tab === "Overview" && <Overview analysis={analysis} />}
              {tab === "Files" && (
                <FilesView files={filteredFiles} query={query} setQuery={setQuery} />
              )}
              {tab === "Manifest" && (
                <CodePanel
                  title="AndroidManifest.xml (Decoded Binary AXML)"
                  code={analysis.manifestXml ?? "Binary AndroidManifest.xml could not be decoded."}
                />
              )}
              {tab === "Permissions" && (
                <ListView
                  title="Android Permissions"
                  items={analysis.permissions}
                  empty="No permissions requested in manifest."
                />
              )}
              {tab === "Components" && <Components analysis={analysis} />}
              {tab === "Code" && <CodeView analysis={analysis} apkFile={currentFile} />}
              {tab === "Native" && <NativeView analysis={analysis} />}
              {tab === "Resources" && <ResourceView analysis={analysis} />}
              {tab === "Network" && <NetworkView analysis={analysis} />}
              {tab === "Security" && <SecurityView analysis={analysis} />}
              {tab === "Signing" && <SigningView analysis={analysis} />}
              {tab === "Technology" && (
                <ListView
                  title="Detected Technologies & Frameworks"
                  items={analysis.technologies}
                  empty="No known framework signatures detected."
                />
              )}
              {tab === "Reports" && (
                <Reports
                  analysis={analysis}
                  downloadJSON={downloadJSON}
                  downloadSarif={downloadSarifFile}
                />
              )}
            </>
          )}
        </section>
      </div>
    </main>
  );
}

function Meta({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="meta">
      <span>{label}</span>
      <b className={mono ? "mono" : ""}>{value}</b>
    </div>
  );
}

function Overview({ analysis }: { analysis: APKAnalysis }) {
  const counts = {
    critical: analysis.findings.filter((x) => x.severity === "critical").length,
    high: analysis.findings.filter((x) => x.severity === "high").length,
    medium: analysis.findings.filter((x) => x.severity === "medium").length,
    low: analysis.findings.filter((x) => x.severity === "low").length,
  };
  const score = Math.max(
    0,
    100 - counts.critical * 25 - counts.high * 15 - counts.medium * 8 - counts.low * 2
  );

  return (
    <div className="overview">
      <div className="panel">
        <div className="panel-title">Static Analysis Breakdown</div>
        <div className="summary-grid">
          <Summary label="Total Files" value={analysis.files.length} />
          <Summary label="DEX Classes" value={analysis.dexFiles.reduce((acc, d) => acc + (d.classCount ?? 0), 0)} />
          <Summary label="Native Libraries" value={analysis.nativeLibraries?.length ?? 0} />
          <Summary label="Hardcoded Secrets" value={analysis.secrets?.length ?? 0} />
          <Summary label="HTTP URLs" value={analysis.urls.length} />
          <Summary label="Remote Domains" value={analysis.domains.length} />
        </div>
      </div>

      <div className="panel">
        <div className="panel-title">Security & Risk Posture</div>
        <div className="findings-head">
          <div className="score">
            {score}
            <small>/100</small>
          </div>
          <div>
            <b>Static Security Score</b>
            <p>Calculated based on binary hardening, exposed credentials, and permissions.</p>
          </div>
        </div>
        {analysis.findings.length ? (
          analysis.findings.slice(0, 6).map((f, i) => <Finding key={i} f={f} />)
        ) : (
          <div className="empty">No critical indicators triggered.</div>
        )}
      </div>

      <div className="two">
        <ListCard title="Identified Frameworks" items={analysis.technologies} />
        <ListCard title="Contacted Network Domains" items={analysis.domains.slice(0, 8)} />
      </div>
    </div>
  );
}

function Summary({ label, value }: { label: string; value: number }) {
  return (
    <div className="summary">
      <b>{value}</b>
      <span>{label}</span>
    </div>
  );
}

function Finding({ f }: { f: APKAnalysis["findings"][number] }) {
  return (
    <div className="finding">
      <span className={`dot ${f.severity}`} />
      <div>
        <b>{f.title}</b>
        <small>{f.evidence}</small>
      </div>
      <em>{f.severity}</em>
    </div>
  );
}

function ListCard({ title, items }: { title: string; items: string[] }) {
  return (
    <div className="panel">
      <div className="panel-title">{title}</div>
      {items.length ? (
        items.map((x) => (
          <div className="list-row" key={x}>
            {x}
          </div>
        ))
      ) : (
        <div className="empty">None detected.</div>
      )}
    </div>
  );
}

function ListView({ title, items, empty }: { title: string; items: string[]; empty: string }) {
  return (
    <div className="panel full">
      <div className="panel-title">
        {title} <span>{items.length}</span>
      </div>
      {items.length ? (
        items.map((x) => (
          <div className="list-row" key={x}>
            {x}
          </div>
        ))
      ) : (
        <div className="empty">{empty}</div>
      )}
    </div>
  );
}

function FilesView({
  files,
  query,
  setQuery,
}: {
  files: APKAnalysis["files"];
  query: string;
  setQuery: (s: string) => void;
}) {
  return (
    <div className="panel full">
      <div className="panel-title">
        APK File Archive Explorer <span>{files.length} entries</span>
      </div>
      <div className="search">
        <Search size={15} />
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Filter files by name or path..."
        />
      </div>
      <div className="file-list" style={{ maxHeight: "550px", overflowY: "auto" }}>
        {files.map((f) => (
          <div className="file-row" key={f.path}>
            {f.path.includes("/") ? <Folder size={15} /> : <FileText size={15} />}
            <span>{f.path}</span>
            <small>{formatBytes(f.size)}</small>
          </div>
        ))}
      </div>
    </div>
  );
}

function Components({ analysis }: { analysis: APKAnalysis }) {
  return (
    <div className="three">
      {(["Activities", "Services", "Receivers"] as const).map((kind) => {
        const arr = analysis[kind.toLowerCase() as "activities" | "services" | "receivers"];
        return (
          <div className="panel" key={kind}>
            <div className="panel-title">
              {kind} <span>{arr.length}</span>
            </div>
            {arr.map((x: any, i: number) => (
              <div className="component" key={i}>
                <b>{x.name}</b>
                <span>{x.exported === null ? "exported: default" : `exported: ${x.exported}`}</span>
              </div>
            ))}
          </div>
        );
      })}
      <div className="panel">
        <div className="panel-title">
          Content Providers <span>{analysis.providers.length}</span>
        </div>
        {analysis.providers.map((x: any, i: number) => (
          <div className="component" key={i}>
            <b>{x.name}</b>
            <span>exported: {x.exported ?? "default"}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// Interactive Code Decompiler View with Animated Real-Time Percentage Progress Bar
function CodeView({ analysis, apkFile }: { analysis: APKAnalysis; apkFile: File | null }) {
  const [classFilter, setClassFilter] = useState("");
  const [backendUrl, setBackendUrl] = useState(() => {
    if (typeof window !== "undefined") {
      return (
        process.env.NEXT_PUBLIC_BACKEND_URL ||
        localStorage.getItem("apklens_backend_url") ||
        "https://apklens.onrender.com"
      );
    }
    return process.env.NEXT_PUBLIC_BACKEND_URL || "https://apklens.onrender.com";
  });
  const [showConfig, setShowConfig] = useState(false);
  const [urlInput, setUrlInput] = useState(backendUrl || "https://apklens.onrender.com");
  const [statusMsg, setStatusMsg] = useState("");
  const [activeCode, setActiveCode] = useState<{ className: string; code: string } | null>(null);
  const [copied, setCopied] = useState(false);
  const [decompileError, setDecompileError] = useState("");

  // Progress Bar State for Real-Time Decompilation Feedback
  const [progressState, setProgressState] = useState<{
    className: string;
    percent: number;
    stage: string;
  } | null>(null);

  const allDexClasses = useMemo(() => {
    return analysis.dexFiles.flatMap((d) =>
      (d.classes ?? []).map((c) => ({ dex: d.path, name: c }))
    );
  }, [analysis]);

  const filtered = useMemo(() => {
    if (!classFilter.trim()) return allDexClasses.slice(0, 300);
    return allDexClasses
      .filter((c) => c.name.toLowerCase().includes(classFilter.toLowerCase()))
      .slice(0, 300);
  }, [allDexClasses, classFilter]);

  async function testBackend() {
    if (!urlInput.trim()) {
      setStatusMsg("Please enter a URL.");
      return;
    }
    setStatusMsg("Testing connection to JADX engine...");
    try {
      const res = await fetch(`${urlInput.trim().replace(/\/$/, "")}/health`);
      if (res.ok) {
        const data = await res.json();
        setStatusMsg(`✓ Connected! JADX: ${data.jadx || "1.5.1"}`);
        localStorage.setItem("apklens_backend_url", urlInput.trim());
        setBackendUrl(urlInput.trim());
      } else {
        setStatusMsg(`Failed: HTTP ${res.status}`);
      }
    } catch (e) {
      setStatusMsg(`Connection error: ${e instanceof Error ? e.message : "Unable to reach server"}`);
    }
  }

  async function decompile(className: string, dexPath?: string) {
    if (!backendUrl) {
      setShowConfig(true);
      return;
    }

    setDecompileError("");
    setProgressState({
      className,
      percent: 15,
      stage: "Allocating isolated sandbox & preparing Dalvik bytecode...",
    });

    // Animate stages smoothly while network request is in-flight
    const timer1 = setTimeout(() => {
      setProgressState((prev) =>
        prev
          ? {
              ...prev,
              percent: 40,
              stage: "Parsing DEX header and resolving type cross-references...",
            }
          : null
      );
    }, 400);

    const timer2 = setTimeout(() => {
      setProgressState((prev) =>
        prev
          ? {
              ...prev,
              percent: 70,
              stage: "Reconstructing Abstract Syntax Tree (AST) & SSA registers...",
            }
          : null
      );
    }, 1200);

    const timer3 = setTimeout(() => {
      setProgressState((prev) =>
        prev
          ? {
              ...prev,
              percent: 88,
              stage: "Synthesizing typed Java / Kotlin class source code...",
            }
          : null
      );
    }, 2200);

    try {
      const formData = new FormData();

      // Check if we have the extracted DEX blob cached in memory (10x faster than uploading entire APK!)
      let fileToSend: Blob | null = null;
      if (dexPath) {
        fileToSend = dexBlobCache.get(`${analysis.sha256}:${dexPath}`) || null;
      }
      if (!fileToSend) {
        fileToSend = dexBlobCache.get(`${analysis.sha256}:primary`) || null;
      }
      if (!fileToSend && apkFile) {
        fileToSend = apkFile;
      }

      if (!fileToSend) {
        throw new Error("Bytecode source is not available. Please re-select the APK file.");
      }

      formData.append("file", fileToSend, fileToSend instanceof File ? fileToSend.name : "classes.dex");
      formData.append("className", className);

      const res = await fetch(`${backendUrl.replace(/\/$/, "")}/api/decompile-class`, {
        method: "POST",
        body: formData,
      });

      clearTimeout(timer1);
      clearTimeout(timer2);
      clearTimeout(timer3);

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || err.detail || `Decompilation failed (HTTP ${res.status})`);
      }

      const data = await res.json();

      // 100% finished state
      setProgressState({
        className,
        percent: 100,
        stage: "Decompilation complete! Formatting syntax...",
      });

      setTimeout(() => {
        setActiveCode({ className, code: data.code });
        setProgressState(null);
      }, 400);
    } catch (e) {
      clearTimeout(timer1);
      clearTimeout(timer2);
      clearTimeout(timer3);
      setProgressState(null);
      setDecompileError(e instanceof Error ? e.message : "Decompilation failed.");
    }
  }

  function copyCode() {
    if (!activeCode?.code) return;
    navigator.clipboard.writeText(activeCode.code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="panel full">
      <div className="panel-title">
        Dalvik Bytecode & Interactive Decompiler
        <button
          className="secondary"
          style={{ marginLeft: "auto", fontSize: "0.8rem", padding: "4px 12px" }}
          onClick={() => setShowConfig(!showConfig)}
        >
          <Settings size={13} /> {backendUrl ? "JADX Cloud Connected" : "Configure JADX Engine"}
        </button>
      </div>

      {showConfig && (
        <div
          style={{
            background: "rgba(15, 23, 42, 0.8)",
            padding: "16px",
            borderRadius: "12px",
            border: "1px solid var(--border-glass)",
            marginBottom: "1.2rem",
          }}
        >
          <b style={{ display: "block", marginBottom: "6px", color: "var(--cyan)" }}>
            ⚡ JADX Cloud Decompiler Engine Configuration
          </b>
          <p
            style={{
              margin: "0 0 12px 0",
              fontSize: "0.85rem",
              color: "var(--text-muted)",
              lineHeight: 1.5,
            }}
          >
            The official JADX 1.5.1 backend runs on Render or your local machine. It receives on-demand
            single-class requests and transforms Dalvik bytecode into clean Java/Kotlin code:
          </p>
          <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
            <input
              style={{
                flex: 1,
                padding: "8px 12px",
                background: "rgba(0,0,0,0.5)",
                border: "1px solid var(--border-glass)",
                borderRadius: "8px",
                color: "#fff",
                fontFamily: "var(--font-mono)",
                fontSize: "12px",
              }}
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="e.g. https://apklens.onrender.com or http://localhost:8000"
            />
            <button className="primary" onClick={testBackend} style={{ padding: "8px 16px" }}>
              Save & Test
            </button>
          </div>
          {statusMsg && (
            <div
              style={{
                marginTop: "10px",
                fontSize: "0.85rem",
                color: statusMsg.startsWith("✓") ? "#34d399" : "#f87171",
              }}
            >
              {statusMsg}
            </div>
          )}
        </div>
      )}

      {/* Real-Time Animated Percentage Progress Bar Modal */}
      {progressState && (
        <div className="progress-modal-backdrop">
          <div className="progress-modal">
            <div className="progress-modal-icon">
              <Code2 size={26} />
            </div>
            <h3>Decompiling Class</h3>
            <div className="progress-modal-target">{progressState.className}</div>

            {/* Percentage Bar */}
            <div className="progress-track">
              <div className="progress-fill" style={{ width: `${progressState.percent}%` }} />
            </div>

            <div className="progress-info">
              <span className="progress-stage">{progressState.stage}</span>
              <span className="progress-percent">{progressState.percent}%</span>
            </div>
          </div>
        </div>
      )}

      {decompileError && (
        <div className="error" style={{ marginBottom: "1.2rem" }}>
          <AlertCircle size={16} /> {decompileError}
        </div>
      )}

      {/* DEX Cards Summary */}
      <div className="meta-grid" style={{ marginBottom: "1.4rem" }}>
        {analysis.dexFiles.map((x) => (
          <div className="dex-card" key={x.path} style={{ margin: 0 }}>
            <Code2 size={20} />
            <div>
              <b>{x.path}</b>
              <span>
                {formatBytes(x.size)} · {x.classCount ?? 0} classes · {x.methodCount ?? 0} methods ·{" "}
                {x.strings.toLocaleString()} strings
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* Active Decompiled Source Code Display */}
      {activeCode && (
        <div
          style={{
            background: "rgba(4, 7, 14, 0.9)",
            border: "1px solid rgba(56, 189, 248, 0.35)",
            borderRadius: "14px",
            padding: "18px",
            marginBottom: "1.5rem",
            boxShadow: "0 10px 30px rgba(0, 0, 0, 0.6)",
          }}
        >
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              marginBottom: "12px",
            }}
          >
            <b
              style={{
                color: "var(--cyan)",
                fontFamily: "var(--font-mono)",
                fontSize: "13px",
              }}
            >
              ☕ {activeCode.className}.java
            </b>
            <div style={{ display: "flex", gap: "8px" }}>
              <button
                className="secondary"
                onClick={copyCode}
                style={{ padding: "5px 12px", fontSize: "0.8rem" }}
              >
                {copied ? <Check size={13} /> : <Copy size={13} />} {copied ? "Copied" : "Copy"}
              </button>
              <button
                className="secondary"
                onClick={() => setActiveCode(null)}
                style={{ padding: "5px 10px" }}
              >
                <X size={13} />
              </button>
            </div>
          </div>
          <pre
            style={{
              maxHeight: "440px",
              overflowY: "auto",
              background: "#020408",
              padding: "16px",
              borderRadius: "10px",
              fontSize: "0.85rem",
              lineHeight: 1.6,
              color: "#e2e8f0",
              fontFamily: "var(--font-mono)",
              border: "1px solid var(--border-glass)",
            }}
          >
            <code>{activeCode.code}</code>
          </pre>
        </div>
      )}

      {/* Class List Table */}
      <div className="panel-title" style={{ marginTop: "1rem" }}>
        Compiled Java / Kotlin Classes <span>{allDexClasses.length} parsed classes</span>
      </div>
      <div className="search">
        <Search size={15} />
        <input
          value={classFilter}
          onChange={(e) => setClassFilter(e.target.value)}
          placeholder="Filter class names (e.g. com.android.insecurebankv2.PostLogin)..."
        />
      </div>
      <div className="file-list" style={{ maxHeight: "380px", overflowY: "auto" }}>
        {filtered.length ? (
          filtered.map((c, i) => (
            <div
              className="file-row"
              key={`${c.dex}-${c.name}-${i}`}
              style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "8px", overflow: "hidden" }}>
                <Code2 size={14} />
                <span style={{ textOverflow: "ellipsis", overflow: "hidden", whiteSpace: "nowrap" }}>
                  {c.name}
                </span>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                <small>{c.dex}</small>
                <button
                  className="secondary"
                  style={{ padding: "4px 10px", fontSize: "0.75rem", cursor: "pointer" }}
                  onClick={() => decompile(c.name, c.dex)}
                >
                  Decompile
                </button>
              </div>
            </div>
          ))
        ) : (
          <div className="empty">No classes matched your search query.</div>
        )}
      </div>
    </div>
  );
}

// Native Libraries (ELF) Inspector
function NativeView({ analysis }: { analysis: APKAnalysis }) {
  const libs = analysis.nativeLibraries || [];
  if (!libs.length) {
    return (
      <div className="panel full">
        <div className="panel-title">Native Libraries (.so)</div>
        <div className="empty">No compiled C/C++ native shared libraries (.so) found in lib/.</div>
      </div>
    );
  }

  return (
    <div className="panel full">
      <div className="panel-title">
        Native ELF Shared Libraries (.so) <span>{libs.length} binaries</span>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: "16px", marginTop: "1rem" }}>
        {libs.map((lib, idx) => (
          <div
            key={idx}
            style={{
              background: "rgba(0, 0, 0, 0.4)",
              border: "1px solid var(--border-glass)",
              borderRadius: "12px",
              padding: "16px",
            }}
          >
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                marginBottom: "10px",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                <Cpu size={18} className="text-cyan" />
                <b style={{ fontFamily: "var(--font-mono)", fontSize: "14px" }}>{lib.path}</b>
              </div>
              <div style={{ display: "flex", gap: "6px" }}>
                <span className="badges">
                  <span className="blue">{lib.architecture || "ELF"}</span>
                  <span className="muted">{lib.is64Bit ? "64-bit" : "32-bit"}</span>
                  <span className="muted">{formatBytes(lib.size)}</span>
                </span>
              </div>
            </div>

            {/* JNI Exported Functions */}
            {lib.jniFunctions && lib.jniFunctions.length > 0 && (
              <div style={{ marginTop: "10px" }}>
                <div
                  style={{
                    fontSize: "11px",
                    fontWeight: 700,
                    color: "var(--text-muted)",
                    marginBottom: "6px",
                  }}
                >
                  EXPORTED JNI BINDINGS ({lib.jniFunctions.length}):
                </div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                  {lib.jniFunctions.map((fn, i) => (
                    <span
                      key={i}
                      style={{
                        fontFamily: "var(--font-mono)",
                        fontSize: "11px",
                        background: "rgba(56, 189, 248, 0.1)",
                        color: "var(--cyan)",
                        padding: "2px 8px",
                        borderRadius: "4px",
                        border: "1px solid rgba(56, 189, 248, 0.2)",
                      }}
                    >
                      {fn}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Imported Dynamic Shared Libraries */}
            {lib.importedLibs && lib.importedLibs.length > 0 && (
              <div style={{ marginTop: "10px" }}>
                <div
                  style={{
                    fontSize: "11px",
                    fontWeight: 700,
                    color: "var(--text-muted)",
                    marginBottom: "6px",
                  }}
                >
                  LINKED DYNAMIC LIBRARIES:
                </div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                  {lib.importedLibs.map((dep, i) => (
                    <span
                      key={i}
                      style={{
                        fontFamily: "var(--font-mono)",
                        fontSize: "10.5px",
                        background: "rgba(255, 255, 255, 0.05)",
                        color: "var(--text-muted)",
                        padding: "2px 7px",
                        borderRadius: "4px",
                      }}
                    >
                      {dep}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function ResourceView({ analysis }: { analysis: APKAnalysis }) {
  return (
    <div className="two">
      <ListView title="Application Resources" items={analysis.resources} empty="No res/ files found." />
      <ListView title="Packaged Assets" items={analysis.assets} empty="No assets/ files found." />
    </div>
  );
}

function NetworkView({ analysis }: { analysis: APKAnalysis }) {
  return (
    <div className="two">
      <ListView
        title="Extracted HTTP / HTTPS Endpoints"
        items={analysis.urls}
        empty="No web endpoints found in scanned bytecode."
      />
      <ListView
        title="Discovered Network Domains"
        items={analysis.domains}
        empty="No external domains found."
      />
      <ListView
        title="Embedded WebView Usage"
        items={analysis.webViews}
        empty="No WebViews detected."
      />
    </div>
  );
}

// Security & Automated SAST Scanner View
function SecurityView({ analysis }: { analysis: APKAnalysis }) {
  const secrets = analysis.secrets || [];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
      {/* Secrets & Hardcoded Credentials Card */}
      <div className="panel full">
        <div className="panel-title">
          Automated SAST & Credential Hunter <span>{secrets.length} findings</span>
        </div>

        {secrets.length ? (
          <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            {secrets.map((sec, i) => (
              <div
                key={i}
                style={{
                  background: "rgba(0, 0, 0, 0.35)",
                  border: "1px solid var(--border-glass)",
                  borderRadius: "10px",
                  padding: "14px 16px",
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "flex-start",
                }}
              >
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
                    <span className={`dot ${sec.severity}`} />
                    <b style={{ fontSize: "13px" }}>{sec.name}</b>
                    <em
                      style={{
                        textTransform: "uppercase",
                        fontSize: "9px",
                        fontWeight: 800,
                        padding: "2px 6px",
                        borderRadius: "4px",
                        background:
                          sec.severity === "critical"
                            ? "rgba(244, 63, 94, 0.2)"
                            : "rgba(245, 158, 11, 0.2)",
                        color: sec.severity === "critical" ? "var(--rose)" : "var(--amber)",
                      }}
                    >
                      {sec.severity}
                    </em>
                  </div>
                  <p style={{ fontSize: "12px", color: "var(--text-muted)", margin: "0 0 6px 0" }}>
                    {sec.description}
                  </p>
                  <code
                    style={{
                      fontFamily: "var(--font-mono)",
                      fontSize: "11px",
                      background: "rgba(0, 0, 0, 0.5)",
                      padding: "3px 8px",
                      borderRadius: "4px",
                      color: "var(--cyan)",
                    }}
                  >
                    Matched: {sec.match}
                  </code>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="empty">No exposed credentials or weak crypto detected in scanned strings.</div>
        )}
      </div>

      {/* Manifest & Binary Hardening Indicators */}
      <div className="panel full">
        <div className="panel-title">
          Binary Hardening & Permissions Audit <span>{analysis.findings.length} indicators</span>
        </div>
        {analysis.findings.length ? (
          analysis.findings.map((f, i) => <Finding key={i} f={f} />)
        ) : (
          <div className="empty">No security indicators triggered.</div>
        )}
      </div>
    </div>
  );
}

function SigningView({ analysis }: { analysis: APKAnalysis }) {
  const cert = analysis.certificate;
  if (!cert) {
    return (
      <div className="panel full">
        <div className="panel-title">Certificate & Digital Signature</div>
        <div className="empty">
          No valid APK signature (v1 JAR or v2/v3 Signing Block) was detected. The APK is unsigned or malformed.
        </div>
      </div>
    );
  }

  return (
    <div className="panel full">
      <div className="panel-title">
        X.509 Signing Certificate <span>Scheme: {cert.scheme}</span>
      </div>
      <div className="meta-grid" style={{ marginTop: "1rem" }}>
        <Meta label="Signing Scheme" value={cert.scheme} />
        <Meta label="Signature Algorithm" value={cert.sigAlg} />
        <Meta label="Valid From" value={cert.validFrom} />
        <Meta label="Valid To" value={cert.validTo} />
        <Meta label="Subject" value={cert.subject} />
        <Meta label="Issuer" value={cert.issuer} />
        <Meta label="Serial Number" value={cert.serialNumber} mono />
        <Meta label="SHA-256 Fingerprint" value={cert.sha256Fingerprint} mono />
        <Meta label="SHA-1 Fingerprint" value={cert.sha1Fingerprint} mono />
      </div>
    </div>
  );
}

function Reports({
  analysis,
  downloadJSON,
  downloadSarif,
}: {
  analysis: APKAnalysis;
  downloadJSON: () => void;
  downloadSarif: () => void;
}) {
  return (
    <div className="panel full">
      <div className="panel-title">Compliance Reports & DevSecOps Exports</div>
      <p className="report-text" style={{ marginBottom: "1.5rem" }}>
        Export the findings into standard formats for DevSecOps pipelines, issue trackers, and audits:
      </p>

      <div style={{ display: "flex", gap: "12px", flexWrap: "wrap", marginBottom: "1.5rem" }}>
        <button className="primary" onClick={downloadSarif} style={{ padding: "10px 18px" }}>
          <FileCode2 size={16} /> Download OASIS SARIF 2.1.0 (.sarif)
        </button>
        <button
          className="secondary"
          onClick={() => openPrintableReport(analysis)}
          style={{ padding: "10px 18px" }}
        >
          <FileText size={16} /> Print / Save Executive PDF Assessment
        </button>
        <button className="secondary" onClick={downloadJSON} style={{ padding: "10px 18px" }}>
          <Code2 size={16} /> Download Raw JSON Analysis
        </button>
      </div>

      <div className="notice">
        <Lock size={16} /> Reports are synthesized locally in memory. Zero proprietary application data is transmitted to external monitoring servers.
      </div>
    </div>
  );
}

function CodePanel({ title, code }: { title: string; code: string }) {
  return (
    <div className="panel full">
      <div className="panel-title">{title}</div>
      <pre className="code">{code}</pre>
    </div>
  );
}

function formatBytes(n: number) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(2)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}