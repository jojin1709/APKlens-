"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import {
  Activity, AlertCircle, Archive, ArrowLeft, ArrowUpRight, Box, Check, CheckCircle2,
  ChevronDown, ChevronRight, Code2, Copy, Cpu, Database, Download, Eye, FileCode2, FileText,
  Folder, Globe, KeyRound, Layers, LayoutDashboard, Link2, Linkedin, Lock, Package, Radio, Search,
  Server, Settings, Shield, ShieldAlert, ShieldCheck, Smartphone,
  Sparkles, Trash2, Upload, X, XCircle, Zap
} from "lucide-react";
import LandingPage from "@/components/LandingPage";
import { analyzeAPK, dexBlobCache } from "@/lib/apk-analyzer";
import { clearAnalyses, deleteAnalysis, listAnalyses, saveAnalysis } from "@/lib/local-db";
import { generateSarif } from "@/lib/sarif-generator";
import { openPrintableReport } from "@/lib/pdf-report-generator";
import { generateMarkdownReport, generateCSVFindings } from "@/lib/export-utils";
import { mapToOWASPTop10 } from "@/lib/owasp-mapper";
import type { APKAnalysis } from "@/types/apk";

type Tab =
  | "Overview"
  | "Files"
  | "Manifest"
  | "Permissions"
  | "Components"
  | "DeepLinks"
  | "Code"
  | "Native"
  | "Resources"
  | "Network"
  | "Security"
  | "OWASP"
  | "Strings"
  | "Signing"
  | "Technology"
  | "Reports";

const tabs: { id: Tab; label: string; icon: React.ReactNode }[] = [
  { id: "Overview", label: "Overview", icon: <LayoutDashboard size={16} /> },
  { id: "Files", label: "File Explorer", icon: <Folder size={16} /> },
  { id: "Manifest", label: "AndroidManifest", icon: <FileCode2 size={16} /> },
  { id: "Permissions", label: "Permissions", icon: <Lock size={16} /> },
  { id: "Components", label: "Components", icon: <Layers size={16} /> },
  { id: "DeepLinks", label: "Deep Links & Schemes", icon: <Link2 size={16} /> },
  { id: "Code", label: "DEX & Decompiler", icon: <Code2 size={16} /> },
  { id: "Native", label: "Native Libraries (.so)", icon: <Cpu size={16} /> },
  { id: "Resources", label: "Resources", icon: <Archive size={16} /> },
  { id: "Network", label: "Network & URLs", icon: <Globe size={16} /> },
  { id: "Security", label: "Security & Secrets", icon: <ShieldAlert size={16} /> },
  { id: "OWASP", label: "OWASP Mobile Top 10", icon: <ShieldCheck size={16} /> },
  { id: "Strings", label: "Bytecode Strings", icon: <Search size={16} /> },
  { id: "Signing", label: "Certificate & Signing", icon: <KeyRound size={16} /> },
  { id: "Technology", label: "Technology Stack", icon: <Zap size={16} /> },
  { id: "Reports", label: "Reports & Exports", icon: <FileText size={16} /> },
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

  function downloadMarkdownFile() {
    if (!analysis) return;
    const md = generateMarkdownReport(analysis);
    const blob = new Blob([md], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${analysis.fileName.replace(/\.apk$/i, "")}-security-audit.md`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function downloadCSVFile() {
    if (!analysis) return;
    const csv = generateCSVFindings(analysis);
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${analysis.fileName.replace(/\.apk$/i, "")}-findings.csv`;
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
      {/* Background Ambience - Atomic Black */}
      <div className="atomic-bg-canvas" aria-hidden="true">
        <div className="atomic-radial-top"></div>
        <div className="atomic-radial-bottom"></div>
        <div className="atomic-mesh-grid"></div>
      </div>

      {/* Topbar */}
      <header className="topbar">
        <div className="brand" onClick={() => setView("landing")} style={{ cursor: "pointer" }}>
          <div className="brandmark">
            <img src="/icon.svg" alt="APKLens" style={{ width: "22px", height: "22px" }} />
          </div>
          <div>
            <div className="brand-title">
              APKLens
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
          <a
            href="https://www.linkedin.com/in/jojin-john/"
            target="_blank"
            rel="noopener noreferrer"
            className="nav-tab-btn"
            style={{ textDecoration: "none", gap: "8px", padding: "4px 10px 4px 6px" }}
            title="Developer: Jojin John (LinkedIn Profile)"
          >
            <img
              src="/jojin.png"
              alt="Jojin John"
              style={{ width: "20px", height: "20px", borderRadius: "50%", objectFit: "cover", border: "1.5px solid rgba(61, 220, 132, 0.45)" }}
            />
            <span>Jojin John</span>
          </a>
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
                  {analysis.icon ? (
                    <img src={analysis.icon} alt="App Icon" className="app-real-icon" />
                  ) : (
                    <div className="android-icon">
                      <Smartphone size={30} />
                    </div>
                  )}
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
              {tab === "DeepLinks" && <DeepLinksView analysis={analysis} />}
              {tab === "Code" && <CodeView analysis={analysis} apkFile={currentFile} />}
              {tab === "Native" && <NativeView analysis={analysis} />}
              {tab === "Resources" && <ResourceView analysis={analysis} />}
              {tab === "Network" && <NetworkView analysis={analysis} />}
              {tab === "Security" && <SecurityView analysis={analysis} />}
              {tab === "OWASP" && <OWASPView analysis={analysis} />}
              {tab === "Strings" && <StringSweeperView analysis={analysis} />}
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
                  downloadMarkdown={downloadMarkdownFile}
                  downloadCSV={downloadCSVFile}
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
  const [query, setQuery] = useState("");

  const groups = [
    {
      key: "activities",
      title: "Activities",
      icon: <Layers size={17} style={{ color: "#818cf8" }} />,
      items: analysis.activities,
      emptyMsg: "No activities declared in AndroidManifest.xml"
    },
    {
      key: "services",
      title: "Background Services",
      icon: <Cpu size={17} style={{ color: "#38bdf8" }} />,
      items: analysis.services,
      emptyMsg: "No background services declared in AndroidManifest.xml"
    },
    {
      key: "receivers",
      title: "Broadcast Receivers",
      icon: <Radio size={17} style={{ color: "#34d399" }} />,
      items: analysis.receivers,
      emptyMsg: "No broadcast receivers declared in AndroidManifest.xml"
    },
    {
      key: "providers",
      title: "Content Providers",
      icon: <Database size={17} style={{ color: "#fbbf24" }} />,
      items: analysis.providers,
      emptyMsg: "No content providers declared in AndroidManifest.xml"
    }
  ];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
      {/* Component Search & Summary Bar */}
      <div className="panel full" style={{ padding: "16px 20px" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "14px" }}>
          <div>
            <div style={{ fontSize: "16px", fontWeight: 700, color: "#ffffff", marginBottom: "4px" }}>
              Android Application Components
            </div>
            <div style={{ fontSize: "13px", color: "var(--text-muted)" }}>
              {analysis.activities.length} Activities · {analysis.services.length} Services · {analysis.receivers.length} Receivers · {analysis.providers.length} Providers
            </div>
          </div>
          <div className="search" style={{ margin: 0, minWidth: "280px" }}>
            <Search size={15} />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search components by class name..."
            />
          </div>
        </div>
      </div>

      {/* 2x2 Grid of Component Groups */}
      <div className="components-grid">
        {groups.map((g) => {
          const filteredItems = g.items.filter((x: any) =>
            !query.trim() || x.name.toLowerCase().includes(query.toLowerCase())
          );

          return (
            <div className="component-panel" key={g.key}>
              <div className="component-panel-head">
                <div className="component-panel-title">
                  {g.icon}
                  <span>{g.title}</span>
                </div>
                <span className="component-count-pill">
                  {filteredItems.length}
                </span>
              </div>

              {filteredItems.length > 0 ? (
                <div style={{ maxHeight: "420px", overflowY: "auto", paddingRight: "4px" }}>
                  {filteredItems.map((x: any, i: number) => {
                    const isExported = x.exported === "true" || x.exported === true;
                    const isPrivate = x.exported === "false" || x.exported === false;

                    return (
                      <div className="component-item" key={i}>
                        <span className="component-item-name">{x.name}</span>
                        <span
                          className={`component-badge ${
                            isExported ? "exported" : isPrivate ? "private" : "default"
                          }`}
                        >
                          {isExported ? "Exported (Public)" : isPrivate ? "Private (Internal)" : "Default"}
                        </span>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div className="component-empty">
                  {g.icon}
                  <span>{query.trim() ? "No matching components found." : g.emptyMsg}</span>
                </div>
              )}
            </div>
          );
        })}
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
  // Persistent Decompiled Cache across tabs within session
  const [decompiledMap, setDecompiledMap] = useState<Record<string, string>>(() => {
    if (typeof window !== "undefined") {
      try {
        const stored = sessionStorage.getItem(`apklens_decompiled_${analysis.id}`);
        return stored ? JSON.parse(stored) : {};
      } catch {}
    }
    return {};
  });

  const [activeClassName, setActiveClassName] = useState<string>(() => {
    if (typeof window !== "undefined") {
      try {
        return sessionStorage.getItem(`apklens_active_class_${analysis.id}`) || "";
      } catch {}
    }
    return "";
  });

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
    // If already in session cache, open immediately with 0ms delay!
    if (decompiledMap[className]) {
      setActiveClassName(className);
      if (typeof window !== "undefined") {
        sessionStorage.setItem(`apklens_active_class_${analysis.id}`, className);
      }
      return;
    }

    if (!backendUrl) {
      setShowConfig(true);
      return;
    }

    setDecompileError("");
    setProgressState({
      className,
      percent: 15,
      stage: "Allocating isolated container & loading Dalvik bytecode...",
    });

    const timer1 = setTimeout(() => {
      setProgressState((prev) =>
        prev
          ? {
              ...prev,
              percent: 42,
              stage: "Parsing DEX header and resolving type cross-references...",
            }
          : null
      );
    }, 450);

    const timer2 = setTimeout(() => {
      setProgressState((prev) =>
        prev
          ? {
              ...prev,
              percent: 72,
              stage: "Reconstructing Abstract Syntax Tree (AST) & SSA registers...",
            }
          : null
      );
    }, 1250);

    const timer3 = setTimeout(() => {
      setProgressState((prev) =>
        prev
          ? {
              ...prev,
              percent: 89,
              stage: "Synthesizing typed Java / Kotlin class source code...",
            }
          : null
      );
    }, 2300);

    try {
      const formData = new FormData();

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

      setProgressState({
        className,
        percent: 100,
        stage: "Decompilation complete! Formatting syntax...",
      });

      setTimeout(() => {
        const nextMap = { ...decompiledMap, [className]: data.code };
        setDecompiledMap(nextMap);
        setActiveClassName(className);
        if (typeof window !== "undefined") {
          sessionStorage.setItem(`apklens_decompiled_${analysis.id}`, JSON.stringify(nextMap));
          sessionStorage.setItem(`apklens_active_class_${analysis.id}`, className);
        }
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

  function closeTab(cls: string, e: React.MouseEvent) {
    e.stopPropagation();
    const nextMap = { ...decompiledMap };
    delete nextMap[cls];
    setDecompiledMap(nextMap);
    const remainingKeys = Object.keys(nextMap);
    const nextActive = remainingKeys.length
      ? activeClassName === cls
        ? remainingKeys[remainingKeys.length - 1]
        : activeClassName
      : "";
    setActiveClassName(nextActive);
    if (typeof window !== "undefined") {
      sessionStorage.setItem(`apklens_decompiled_${analysis.id}`, JSON.stringify(nextMap));
      sessionStorage.setItem(`apklens_active_class_${analysis.id}`, nextActive);
    }
  }

  function copyCode() {
    if (!activeClassName || !decompiledMap[activeClassName]) return;
    navigator.clipboard.writeText(decompiledMap[activeClassName]);
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

      {/* Enhanced Animated Radar Progress Bar Modal */}
      {progressState && (
        <div className="progress-modal-backdrop">
          <div className="progress-modal">
            <div className="progress-modal-radar">
              <div className="radar-glow"></div>
              <div className="radar-ring"></div>
              <Code2 size={26} className="text-cyan" style={{ position: "relative", zIndex: 2 }} />
            </div>
            <h3>Decompiling Class</h3>
            <div className="progress-modal-target">{progressState.className}</div>

            {/* Percentage Bar */}
            <div className="progress-track">
              <div className="progress-fill" style={{ width: `${progressState.percent}%` }} />
            </div>

            <div className="progress-info">
              <span className="progress-stage">
                <span className="status-dot" style={{ display: "inline-block", width: "6px", height: "6px", marginRight: "6px" }}></span>
                {progressState.stage}
              </span>
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

      {/* Active Decompiled Classes Tabs Bar & Code Viewer */}
      {activeClassName && decompiledMap[activeClassName] && (
        <div
          style={{
            background: "rgba(4, 7, 14, 0.95)",
            border: "1px solid rgba(56, 189, 248, 0.35)",
            borderRadius: "16px",
            padding: "20px",
            marginBottom: "1.5rem",
            boxShadow: "0 14px 40px rgba(0, 0, 0, 0.7)",
          }}
        >
          {/* Tabs Bar for Open Decompiled Classes */}
          <div className="decompiled-tabs-bar">
            {Object.keys(decompiledMap).map((cls) => {
              const shortName = cls.split(".").pop() || cls;
              const isActive = cls === activeClassName;
              return (
                <div
                  key={cls}
                  className={`decompiled-tab-btn ${isActive ? "active" : ""}`}
                  onClick={() => {
                    setActiveClassName(cls);
                    sessionStorage.setItem(`apklens_active_class_${analysis.id}`, cls);
                  }}
                  title={cls}
                >
                  <Code2 size={13} className={isActive ? "text-cyan" : ""} />
                  <span>{shortName}.java</span>
                  <button
                    className="decompiled-tab-close"
                    onClick={(e) => closeTab(cls, e)}
                    title="Close tab"
                  >
                    <X size={12} />
                  </button>
                </div>
              );
            })}
          </div>

          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              marginBottom: "14px",
              paddingBottom: "10px",
              borderBottom: "1px solid rgba(255, 255, 255, 0.06)",
            }}
          >
            <div>
              <b
                style={{
                  color: "var(--cyan)",
                  fontFamily: "var(--font-mono)",
                  fontSize: "13.5px",
                }}
              >
                ☕ {activeClassName}.java
              </b>
              <span style={{ fontSize: "11.5px", color: "var(--text-faint)", marginLeft: "10px" }}>
                Saved in local session
              </span>
            </div>
            <div style={{ display: "flex", gap: "8px" }}>
              <button
                className="secondary"
                onClick={copyCode}
                style={{ fontSize: "0.8rem", padding: "5px 12px" }}
              >
                {copied ? <Check size={13} /> : <Copy size={13} />}
                <span>{copied ? "Copied!" : "Copy Source"}</span>
              </button>
              <button
                className="secondary"
                onClick={() => {
                  const blob = new Blob([decompiledMap[activeClassName]], { type: "text/plain" });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement("a");
                  a.href = url;
                  a.download = `${activeClassName.split(".").pop() || "Class"}.java`;
                  a.click();
                  URL.revokeObjectURL(url);
                }}
                style={{ fontSize: "0.8rem", padding: "5px 12px" }}
              >
                <Download size={13} />
                <span>Download .java</span>
              </button>
            </div>
          </div>

          <pre
            className="code"
            style={{
              maxHeight: "560px",
              margin: 0,
              fontSize: "12.5px",
              lineHeight: 1.6,
              background: "#03060d",
            }}
          >
            <code>{decompiledMap[activeClassName]}</code>
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
                  {decompiledMap[c.name] ? "View Code" : "Decompile"}
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

function DeepLinksView({ analysis }: { analysis: APKAnalysis }) {
  const [filter, setFilter] = useState("");
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);

  const list = (analysis.deepLinks || []).filter(
    (dl) =>
      dl.uri.toLowerCase().includes(filter.toLowerCase()) ||
      dl.activity.toLowerCase().includes(filter.toLowerCase()) ||
      dl.scheme.toLowerCase().includes(filter.toLowerCase())
  );

  function copy(text: string, id: string) {
    navigator.clipboard.writeText(text);
    setCopiedCmd(id);
    setTimeout(() => setCopiedCmd(null), 2000);
  }

  return (
    <div className="panel full">
      <div className="panel-title">
        Deep Links & Custom URI Schemes <span>{analysis.deepLinks?.length || 0} endpoints</span>
      </div>
      <p style={{ fontSize: "13px", color: "var(--text-muted)", marginBottom: "16px" }}>
        Auditing all browsable URI schemes and deep links declared in AndroidManifest.xml. These endpoints can be triggered by external web pages and malicious applications.
      </p>

      <div className="search" style={{ marginBottom: "16px" }}>
        <Search size={15} />
        <input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter deep links by scheme, host, or activity..."
        />
      </div>

      {list.length > 0 ? (
        <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
          {list.map((dl, i) => (
            <div
              key={i}
              style={{
                background: "rgba(15, 23, 42, 0.4)",
                border: "1px solid var(--border-glass)",
                borderRadius: "12px",
                padding: "16px",
                display: "flex",
                flexDirection: "column",
                gap: "10px",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "10px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                  <span
                    style={{
                      background: "rgba(99, 102, 241, 0.15)",
                      color: "#818cf8",
                      border: "1px solid rgba(99, 102, 241, 0.3)",
                      padding: "3px 10px",
                      borderRadius: "6px",
                      fontFamily: "var(--font-mono)",
                      fontSize: "12px",
                      fontWeight: 700,
                    }}
                  >
                    {dl.scheme}://
                  </span>
                  <b style={{ fontFamily: "var(--font-mono)", fontSize: "13.5px", color: "#ffffff" }}>
                    {dl.uri}
                  </b>
                </div>

                <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                  {dl.isBrowsable && (
                    <span className="component-badge exported">Browsable</span>
                  )}
                  <button
                    className="secondary"
                    onClick={() => copy(dl.adbCommand, `adb-${i}`)}
                    style={{ padding: "4px 10px", fontSize: "11.5px" }}
                  >
                    {copiedCmd === `adb-${i}` ? <Check size={12} /> : <Copy size={12} />}
                    <span>{copiedCmd === `adb-${i}` ? "Copied ADB!" : "Copy ADB PoC"}</span>
                  </button>
                </div>
              </div>

              <div style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                Target Activity: <code style={{ color: "#38bdf8", fontFamily: "var(--font-mono)" }}>{dl.activity}</code>
              </div>

              <div
                style={{
                  background: "#03060d",
                  padding: "8px 12px",
                  borderRadius: "8px",
                  fontFamily: "var(--font-mono)",
                  fontSize: "11.5px",
                  color: "#94a3b8",
                  overflowX: "auto",
                  border: "1px solid rgba(255, 255, 255, 0.05)",
                }}
              >
                {dl.adbCommand}
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="empty">
          No deep links or custom URI schemes matched your criteria.
        </div>
      )}
    </div>
  );
}

function OWASPView({ analysis }: { analysis: APKAnalysis }) {
  const categories = useMemo(() => mapToOWASPTop10(analysis), [analysis]);
  const failCount = categories.filter((c) => c.status === "fail").length;
  const warnCount = categories.filter((c) => c.status === "warn").length;
  const passCount = categories.filter((c) => c.status === "pass").length;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
      {/* Scorecard Header */}
      <div className="panel full" style={{ padding: "20px 24px" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "16px" }}>
          <div>
            <div style={{ fontSize: "18px", fontWeight: 800, color: "#ffffff", marginBottom: "4px" }}>
              OWASP Mobile Top 10 (2024 / MASVS) Compliance Matrix
            </div>
            <div style={{ fontSize: "13px", color: "var(--text-muted)" }}>
              Official mobile security compliance framework mapping for Android applications.
            </div>
          </div>

          <div style={{ display: "flex", gap: "12px" }}>
            <span style={{ padding: "6px 14px", borderRadius: "10px", background: "rgba(239, 68, 68, 0.12)", color: "#f87171", border: "1px solid rgba(239, 68, 68, 0.3)", fontSize: "12px", fontWeight: 700 }}>
              {failCount} FAILED
            </span>
            <span style={{ padding: "6px 14px", borderRadius: "10px", background: "rgba(245, 158, 11, 0.12)", color: "#fbbf24", border: "1px solid rgba(245, 158, 11, 0.3)", fontSize: "12px", fontWeight: 700 }}>
              {warnCount} WARNINGS
            </span>
            <span style={{ padding: "6px 14px", borderRadius: "10px", background: "rgba(52, 211, 153, 0.12)", color: "#34d399", border: "1px solid rgba(52, 211, 153, 0.3)", fontSize: "12px", fontWeight: 700 }}>
              {passCount} PASSED
            </span>
          </div>
        </div>
      </div>

      {/* 10 Categories Grid */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(420px, 1fr))", gap: "16px" }}>
        {categories.map((cat) => (
          <div
            key={cat.id}
            style={{
              background: "var(--bg-card)",
              border: `1px solid ${cat.status === "fail" ? "rgba(239, 68, 68, 0.35)" : cat.status === "warn" ? "rgba(245, 158, 11, 0.35)" : "var(--border-glass)"}`,
              borderRadius: "16px",
              padding: "20px",
              display: "flex",
              flexDirection: "column",
              gap: "12px",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                <span
                  style={{
                    background: "rgba(255, 255, 255, 0.05)",
                    fontFamily: "var(--font-mono)",
                    fontSize: "12px",
                    fontWeight: 800,
                    padding: "3px 8px",
                    borderRadius: "6px",
                    color: "#ffffff",
                  }}
                >
                  {cat.id}
                </span>
                <b style={{ color: "#ffffff", fontSize: "14.5px" }}>{cat.name}</b>
              </div>
              <span
                className={`component-badge ${
                  cat.status === "fail" ? "exported" : cat.status === "warn" ? "default" : "private"
                }`}
                style={{
                  background: cat.status === "fail" ? "rgba(239, 68, 68, 0.18)" : cat.status === "warn" ? "rgba(245, 158, 11, 0.18)" : "rgba(52, 211, 153, 0.18)",
                  color: cat.status === "fail" ? "#f87171" : cat.status === "warn" ? "#fbbf24" : "#34d399",
                }}
              >
                {cat.status.toUpperCase()}
              </span>
            </div>

            <div style={{ fontSize: "12.5px", color: "var(--text-muted)", lineHeight: 1.5 }}>
              {cat.description}
            </div>

            {/* Findings List */}
            <div style={{ background: "rgba(0, 0, 0, 0.3)", borderRadius: "8px", padding: "10px 12px", fontSize: "12px" }}>
              <b style={{ color: "#cbd5e1", display: "block", marginBottom: "4px" }}>Audit Evidence:</b>
              {cat.findings.length ? (
                <ul style={{ margin: 0, paddingLeft: "16px", color: "#94a3b8" }}>
                  {cat.findings.map((f, i) => (
                    <li key={i} style={{ marginBottom: "2px" }}>{f}</li>
                  ))}
                </ul>
              ) : (
                <span style={{ color: "#34d399" }}>No vulnerabilities detected for this category.</span>
              )}
            </div>

            {/* Remediation */}
            <div style={{ fontSize: "12px", color: "#818cf8", lineHeight: 1.4 }}>
              <b>Remediation:</b> {cat.remediation}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function StringSweeperView({ analysis }: { analysis: APKAnalysis }) {
  const [filter, setFilter] = useState("");
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const list = useMemo(() => {
    const raw = analysis.strings || [];
    if (!filter.trim()) return raw.slice(0, 400);
    return raw.filter((s) => s.toLowerCase().includes(filter.toLowerCase())).slice(0, 400);
  }, [analysis.strings, filter]);

  function copy(str: string, index: number) {
    navigator.clipboard.writeText(str);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  }

  return (
    <div className="panel full">
      <div className="panel-title">
        DEX Bytecode String Pool Sweeper <span>{analysis.strings?.length || 0} unique strings</span>
      </div>
      <p style={{ fontSize: "13px", color: "var(--text-muted)", marginBottom: "16px" }}>
        Examines strings extracted from Dalvik Executable (DEX) header tables across all compiled classes.
      </p>

      <div className="search" style={{ marginBottom: "16px" }}>
        <Search size={15} />
        <input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Search strings (endpoints, internal tags, method signatures, keys)..."
        />
      </div>

      <div style={{ maxHeight: "560px", overflowY: "auto" }}>
        {list.length ? (
          list.map((str, i) => (
            <div
              key={i}
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                padding: "8px 12px",
                borderRadius: "8px",
                background: i % 2 === 0 ? "rgba(255, 255, 255, 0.015)" : "transparent",
                borderBottom: "1px solid rgba(255, 255, 255, 0.03)",
                fontFamily: "var(--font-mono)",
                fontSize: "12px",
                color: "#cbd5e1",
              }}
            >
              <span style={{ wordBreak: "break-all", marginRight: "12px" }}>{str}</span>
              <button
                className="secondary"
                onClick={() => copy(str, i)}
                style={{ padding: "3px 8px", fontSize: "11px", flexShrink: 0 }}
              >
                {copiedIndex === i ? <Check size={11} /> : <Copy size={11} />}
              </button>
            </div>
          ))
        ) : (
          <div className="empty">No matching bytecode strings found.</div>
        )}
      </div>
    </div>
  );
}

function Reports({
  analysis,
  downloadJSON,
  downloadSarif,
  downloadMarkdown,
  downloadCSV,
}: {
  analysis: APKAnalysis;
  downloadJSON: () => void;
  downloadSarif: () => void;
  downloadMarkdown: () => void;
  downloadCSV: () => void;
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
        <button className="secondary" onClick={downloadMarkdown} style={{ padding: "10px 18px" }}>
          <FileText size={16} /> Bug Bounty Markdown Report (.md)
        </button>
        <button className="secondary" onClick={downloadCSV} style={{ padding: "10px 18px" }}>
          <Download size={16} /> Export Findings CSV (.csv)
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