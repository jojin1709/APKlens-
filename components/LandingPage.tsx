"use client";

import React, { useState } from "react";
import {
  Shield, Lock, Zap, Code2, Cpu, FileText, CheckCircle2, ArrowRight,
  Upload, Layers, Eye, ShieldCheck, Check, Laptop, FileCode,
  Download, ArrowUpRight, Linkedin, Github, Heart, Link as LinkIcon,
  Search, Database, Key, Sparkles, ChevronDown, CheckCircle, XCircle
} from "lucide-react";

interface LandingPageProps {
  onLaunch: () => void;
  onFileSelect: (file: File) => void;
  onLoadSample?: () => void;
}

export default function LandingPage({ onLaunch, onFileSelect, onLoadSample }: LandingPageProps) {
  const [dragActive, setDragActive] = useState(false);
  const [activeDropdown, setActiveDropdown] = useState<string | null>(null);
  const [selectedOrbitModule, setSelectedOrbitModule] = useState<number>(0);

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragActive(false);
    if (e.dataTransfer.files?.[0]) {
      const file = e.dataTransfer.files[0];
      const validExts = [".apk", ".aab", ".xapk", ".apks"];
      const ext = file.name.toLowerCase().slice(file.name.lastIndexOf("."));
      if (validExts.includes(ext)) {
        onFileSelect(file);
      }
    }
  };

  const orbitModules = [
    {
      id: 0,
      name: "AXML Manifest Engine",
      short: "AXML Decoder",
      tag: "Binary Decoder",
      icon: <Layers size={18} className="text-cyan" />,
      desc: "Decodes binary compiled AndroidManifest.xml chunks, extracting permissions, exported components, and SDK limits.",
      metric: "Sub-10ms Decode",
      deg: 0
    },
    {
      id: 1,
      name: "Dalvik DEX Sweeper",
      short: "DEX Sweeper",
      tag: "Bytecode Parser",
      icon: <Code2 size={18} className="text-indigo" />,
      desc: "Parses Multi-DEX header tables, method references, class pools, and sweeps up to 12,000 raw strings.",
      metric: "Multi-DEX Ready",
      deg: 45
    },
    {
      id: 2,
      name: "OWASP Mobile Top 10",
      short: "OWASP 2024",
      tag: "Compliance Matrix",
      icon: <ShieldCheck size={18} className="text-emerald" />,
      desc: "Maps security posture against official 2024 OWASP Mobile standard (M1–M10) with pass/fail telemetry.",
      metric: "2024 MASVS",
      deg: 90
    },
    {
      id: 3,
      name: "Deep Link Hunter",
      short: "Deep Links",
      tag: "Scheme Extractor",
      icon: <LinkIcon size={18} className="text-blue" />,
      desc: "Extracts custom URL schemes and browsable intent filters with click-to-copy adb reproduction PoCs.",
      metric: "ADB PoC Ready",
      deg: 135
    },
    {
      id: 4,
      name: "Secret & Key Hunter",
      short: "Secret Hunter",
      tag: "Entropy & SAST",
      icon: <Key size={18} className="text-amber" />,
      desc: "Sweeps for OpenAI API keys, AWS credentials, GitHub tokens, DB URIs, and dynamic code loading.",
      metric: "18+ SAST Rules",
      deg: 180
    },
    {
      id: 5,
      name: "ELF Native Inspector",
      short: "NDK (.so)",
      tag: "Binary Auditing",
      icon: <Cpu size={18} className="text-purple" />,
      desc: "Audits compiled C/C++ shared libraries (.so), identifying ARM64/x86 targets and exported JNI entry points.",
      metric: "ELF32 & ELF64",
      deg: 225
    },
    {
      id: 6,
      name: "JADX AST Decompiler",
      short: "JADX Source",
      tag: "Source Reverse Eng",
      icon: <FileCode size={18} className="text-pink" />,
      desc: "Targeted single-class Java & Kotlin AST decompilation directly in browser memory with syntax highlighting.",
      metric: "Java & Kotlin",
      deg: 270
    },
    {
      id: 7,
      name: "DevSecOps & Bug Bounty",
      short: "Bug Bounty Export",
      tag: "Report Generation",
      icon: <FileText size={18} className="text-emerald" />,
      desc: "Export HackerOne/Bugcrowd Markdown bug bounty reports, OASIS SARIF 2.1.0, and RFC-4180 CSV findings.",
      metric: "SARIF & Markdown",
      deg: 315
    }
  ];

  return (
    <div className="landing-wrap">
      {/* Atomic Deep Atmospheric Canvas */}
      <div className="atomic-bg-canvas">
        <div className="atomic-radial-top"></div>
        <div className="atomic-radial-bottom"></div>
        <div className="atomic-mesh-grid"></div>
      </div>

      {/* Floating Glassmorphic Top Navbar */}
      <nav className="atomic-nav">
        <div className="atomic-nav-inner">
          {/* Logo Mark with signature 45-degree hover rotation */}
          <div className="atomic-brand" onClick={onLaunch} style={{ cursor: "pointer" }}>
            <div className="atomic-logo-box">
              <img src="/icon.svg" alt="APKLens logo" className="atomic-logo-img" />
            </div>
            <div className="atomic-brand-text">
              <div className="atomic-brand-name">APKLens</div>
              <span className="atomic-brand-sub">Security & Architecture Suite</span>
            </div>
          </div>

          {/* Navigation Links with animated hover line & dropdowns */}
          <div className="atomic-nav-center">
            {/* Capabilities Dropdown */}
            <div 
              className="atomic-nav-dd"
              onMouseEnter={() => setActiveDropdown("caps")}
              onMouseLeave={() => setActiveDropdown(null)}
            >
              <button className="atomic-nav-link dd-trigger">
                <span>Capabilities</span>
                <ChevronDown size={14} className={`dd-chev ${activeDropdown === "caps" ? "open" : ""}`} />
              </button>

              {activeDropdown === "caps" && (
                <div className="atomic-dd-panel open">
                  <div className="atomic-dd-links">
                    <a href="#orbit-stage" className="atomic-dd-link" onClick={() => setActiveDropdown(null)}>
                      <span className="atomic-dd-icon">
                        <LinkIcon size={18} className="text-blue" />
                      </span>
                      <span className="atomic-dd-copy">
                        <span className="title">Deep Link Hunter</span>
                        <span className="sub">Browsable schemes & ADB PoCs</span>
                      </span>
                    </a>
                    <a href="#orbit-stage" className="atomic-dd-link" onClick={() => setActiveDropdown(null)}>
                      <span className="atomic-dd-icon">
                        <ShieldCheck size={18} className="text-emerald" />
                      </span>
                      <span className="atomic-dd-copy">
                        <span className="title">OWASP Mobile Top 10</span>
                        <span className="sub">2024 compliance matrix (M1–M10)</span>
                      </span>
                    </a>
                    <a href="#orbit-stage" className="atomic-dd-link" onClick={() => setActiveDropdown(null)}>
                      <span className="atomic-dd-icon">
                        <Key size={18} className="text-amber" />
                      </span>
                      <span className="atomic-dd-copy">
                        <span className="title">Secret & SAST Sweeper</span>
                        <span className="sub">Entropy, tokens & API keys</span>
                      </span>
                    </a>
                    <a href="#orbit-stage" className="atomic-dd-link" onClick={() => setActiveDropdown(null)}>
                      <span className="atomic-dd-icon">
                        <FileCode size={18} className="text-purple" />
                      </span>
                      <span className="atomic-dd-copy">
                        <span className="title">JADX AST Decompiler</span>
                        <span className="sub">Targeted Dalvik source reverse eng</span>
                      </span>
                    </a>
                  </div>
                </div>
              )}
            </div>

            <a href="#orbit-stage" className="atomic-nav-link">Live Orbit</a>
            <a href="#comparison" className="atomic-nav-link">Local vs Cloud</a>
            <a href="#how-it-works" className="atomic-nav-link">How It Works</a>
            <a href="#developer" className="atomic-nav-link">Developer</a>
          </div>

          {/* Right Action: White solid button */}
          <div className="atomic-nav-right">
            <button className="atomic-btn-solid" onClick={onLaunch}>
              <span>Launch Console</span>
              <ArrowRight size={14} />
            </button>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="atomic-hero">
        <div className="atomic-hero-inner">
          {/* Status Badge with Ping Animation */}
          <div className="atomic-badge">
            <span className="atomic-pulse-wrap">
              <span className="atomic-pulse-dot"></span>
              <span className="atomic-pulse-ring"></span>
            </span>
            <span>100% In-Browser Inspection • Zero Cloud Uploads • Free & Private</span>
          </div>

          {/* Hero Headline with tight negative tracking */}
          <h1 className="atomic-hero-title">
            The private, in-browser <br />
            <span className="atomic-hero-gradient">Android APK security suite.</span>
          </h1>

          <p className="atomic-hero-sub">
            Decode binary manifests, inspect Dalvik bytecode, hunt exposed secrets, map OWASP Mobile Top 10 vulnerabilities,
            and decompile Java/Kotlin source code—running completely in your local browser sandbox.
          </p>

          {/* Interactive Drag & Drop Box */}
          <div
            className={`atomic-dropzone ${dragActive ? "drag-over" : ""}`}
            onDragOver={(e) => { e.preventDefault(); setDragActive(true); }}
            onDragLeave={() => setDragActive(false)}
            onDrop={handleDrop}
            onClick={() => {
              const input = document.createElement("input");
              input.type = "file";
              input.accept = ".apk,application/vnd.android.package-archive";
              input.onchange = (e) => {
                const f = (e.target as HTMLInputElement).files?.[0];
                if (f) onFileSelect(f);
              };
              input.click();
            }}
          >
            <div className="dropzone-squircle">
              <Upload size={26} />
            </div>
            <div className="dropzone-text">
              <h3>Drop your Android APK here or <span className="browse-text">browse files</span></h3>
              <p>Zero bytes uploaded to external servers. Safe for proprietary, pre-release, and NDA builds.</p>
            </div>
            <div className="dropzone-pills">
              <span className="pill-secure"><Lock size={12} /> Local Sandbox</span>
              <span className="pill-fmt">Split APKs</span>
              <span className="pill-fmt">Multi-DEX</span>
              <span className="pill-fmt">Native NDK (.so)</span>
              <span className="pill-fmt">OWASP 2024</span>
            </div>
          </div>

          {/* Action Row */}
          <div className="atomic-hero-ctas">
            <button className="atomic-btn-solid is-large" onClick={onLaunch}>
              <span>Open APKLens Console</span>
              <ArrowRight size={16} />
            </button>
            {onLoadSample && (
              <button 
                type="button" 
                className="atomic-btn-outline" 
                style={{ borderColor: "rgba(56, 189, 248, 0.4)", color: "#38bdf8" }}
                onClick={(e) => {
                  e.stopPropagation();
                  onLoadSample();
                }}
                title="Loads the authentic InsecureBankv2 vulnerable banking APK for instant zero-setup testing"
              >
                <Sparkles size={16} />
                <span>Load Sample APK (InsecureBankv2)</span>
              </button>
            )}
            <a 
              href="https://github.com/jojin1709/APKlens-" 
              target="_blank" 
              rel="noopener noreferrer" 
              className="atomic-btn-outline"
            >
              <Github size={16} />
              <span>View Source on GitHub</span>
            </a>
          </div>
        </div>
      </section>

      {/* ============================================================ */}
      {/* ATOMIC REVOLVING 3D ORBIT STAGE (Signature Atomic Chat Animation) */}
      {/* ============================================================ */}
      <section id="orbit-stage" className="atomic-orbit-showcase-section">
        <div className="atomic-section-header">
          <div className="atomic-section-tag">LIVE DYNAMIC ORBIT</div>
          <h2 className="atomic-section-title">8 In-Browser Static Inspection Engines</h2>
          <p className="atomic-section-desc">
            Hover over the revolving orbit or click any engine to inspect real-time static triage capabilities.
          </p>
        </div>

        {/* Orbit Rotating Arena */}
        <div className="orbit-stage-arena">
          {/* Central Halo Glow */}
          <div className="orbit-core-halo"></div>

          {/* Concentric Orbital Tracks */}
          <div className="orbit-track-outer">
            {/* Inner Revolving Orbit Ring */}
            <div className="orbit-track-inner">
              {orbitModules.map((mod, idx) => {
                const angleRad = (mod.deg * Math.PI) / 180;
                // Radius in pixels for orbit circle (230px radius)
                const radius = 230;
                const x = Math.round(radius * Math.cos(angleRad));
                const y = Math.round(radius * Math.sin(angleRad));

                return (
                  <div
                    key={mod.id}
                    className="orbit-satellite"
                    style={{
                      transform: `translate(${x}px, ${y}px)`
                    }}
                    onClick={() => setSelectedOrbitModule(mod.id)}
                  >
                    <div className={`satellite-pill ${selectedOrbitModule === mod.id ? "active" : ""}`}>
                      <span className="satellite-icon">{mod.icon}</span>
                      <span className="satellite-label">{mod.short}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Central Centerpiece Core */}
          <div className="orbit-center-core" onClick={onLaunch}>
            <div className="core-logo-box">
              <img src="/icon.svg" alt="APKLens" className="core-logo-img" />
            </div>
            <div className="core-name">APKLens Core</div>
            <div className="core-status">
              <span className="atomic-pulse-dot"></span>
              <span>Online Engine</span>
            </div>
          </div>
        </div>

        {/* Selected Module Live Card Preview Below Arena */}
        <div className="orbit-preview-wrap">
          <div className="stage-card">
            <div className="stage-card-top">
              <div className="stage-icon-box">
                {orbitModules[selectedOrbitModule].icon}
              </div>
              <div>
                <div className="stage-badge">{orbitModules[selectedOrbitModule].tag}</div>
                <h3 className="stage-title">{orbitModules[selectedOrbitModule].name}</h3>
              </div>
              <div className="stage-metric-badge">{orbitModules[selectedOrbitModule].metric}</div>
            </div>

            <p className="stage-desc">{orbitModules[selectedOrbitModule].desc}</p>

            <div className="stage-specs">
              {selectedOrbitModule === 0 && (
                <div className="spec-list">
                  <div className="spec-row"><span className="spec-k">Format:</span><span className="spec-v">Compiled Android Binary XML (AXML) Chunk Format</span></div>
                  <div className="spec-row"><span className="spec-k">Data Extracted:</span><span className="spec-v">Package name, versionCode, minSdkVersion, permissions, exported components</span></div>
                  <div className="spec-row"><span className="spec-k">Execution:</span><span className="spec-v">Pure TypeScript ArrayBuffer parser in Web Worker</span></div>
                </div>
              )}
              {selectedOrbitModule === 1 && (
                <div className="spec-list">
                  <div className="spec-row"><span className="spec-k">Bytecode Format:</span><span className="spec-v">DEX 035, DEX 037, DEX 038, Multi-DEX classes2..N.dex</span></div>
                  <div className="spec-row"><span className="spec-k">String Pool:</span><span className="spec-v">Instant sweep of up to 12,000 raw strings with live regex search</span></div>
                  <div className="spec-row"><span className="spec-k">Disassembly:</span><span className="spec-v">Class definitions, superclasses, interfaces, and method bytecode</span></div>
                </div>
              )}
              {selectedOrbitModule === 2 && (
                <div className="spec-list">
                  <div className="spec-row"><span className="spec-k">Standard:</span><span className="spec-v">OWASP Mobile Top 10 (2024 Edition / MASVS)</span></div>
                  <div className="spec-row"><span className="spec-k">Coverage:</span><span className="spec-v">M1 (Improper Credential Usage) through M10 (Extraneous Functionality)</span></div>
                  <div className="spec-row"><span className="spec-k">Remediation:</span><span className="spec-v">Actionable remediation guides and security scorecards</span></div>
                </div>
              )}
              {selectedOrbitModule === 3 && (
                <div className="spec-list">
                  <div className="spec-row"><span className="spec-k">Schemes Detected:</span><span className="spec-v">Custom URI schemes (e.g. app://), HTTP(S) App Links</span></div>
                  <div className="spec-row"><span className="spec-k">Browsable Intent:</span><span className="spec-v">Flags high-risk attack surfaces callable from browser</span></div>
                  <div className="spec-row"><span className="spec-k">PoC Generation:</span><span className="spec-v">One-click ADB reproduction command for device verification</span></div>
                </div>
              )}
              {selectedOrbitModule === 4 && (
                <div className="spec-list">
                  <div className="spec-row"><span className="spec-k">Heuristics:</span><span className="spec-v">Shannon entropy calculator + high-fidelity regex signatures</span></div>
                  <div className="spec-row"><span className="spec-k">Targets:</span><span className="spec-v">OpenAI keys, AWS credentials, GitHub PATs, Firebase DBs, Stripe, Twilio</span></div>
                  <div className="spec-row"><span className="spec-k">Risk Masking:</span><span className="spec-v">Automatic token masking to prevent screen capture leakage</span></div>
                </div>
              )}
              {selectedOrbitModule === 5 && (
                <div className="spec-list">
                  <div className="spec-row"><span className="spec-k">Architectures:</span><span className="spec-v">arm64-v8a, armeabi-v7a, x86, x86_64 ELF binaries</span></div>
                  <div className="spec-row"><span className="spec-k">Symbol Analysis:</span><span className="spec-v">Exported JNI functions (Java_*), JNI_OnLoad, dynamic dependencies</span></div>
                  <div className="spec-row"><span className="spec-k">Safety:</span><span className="spec-v">Endianness verification and section header validation</span></div>
                </div>
              )}
              {selectedOrbitModule === 6 && (
                <div className="spec-list">
                  <div className="spec-row"><span className="spec-k">Decompiler:</span><span className="spec-v">Integrated JADX 1.5.0 AST source decompiler</span></div>
                  <div className="spec-row"><span className="spec-k">Targeted Mode:</span><span className="spec-v">Decompiles only the selected class to prevent memory bloat</span></div>
                  <div className="spec-row"><span className="spec-k">Telemetry:</span><span className="spec-v">Real-time percentage progress streaming over Web Worker</span></div>
                </div>
              )}
              {selectedOrbitModule === 7 && (
                <div className="spec-list">
                  <div className="spec-row"><span className="spec-k">Bug Bounty:</span><span className="spec-v">HackerOne & Bugcrowd markdown report format (.md)</span></div>
                  <div className="spec-row"><span className="spec-k">DevSecOps:</span><span className="spec-v">OASIS SARIF 2.1.0 JSON for GitHub & GitLab CI/CD scanning</span></div>
                  <div className="spec-row"><span className="spec-k">Spreadsheet:</span><span className="spec-v">RFC-4180 CSV export for security tracking & Jira import</span></div>
                </div>
              )}
            </div>

            <div className="stage-actions">
              <button className="atomic-btn-solid" onClick={onLaunch}>
                <span>Inspect With Your APK</span>
                <ArrowRight size={14} />
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* Comparison Section (Styled exactly like Atomic Chat's "Local vs Cloud AI") */}
      <section id="comparison" className="atomic-section">
        <div className="atomic-section-header">
          <div className="atomic-section-tag">ZERO CLOUD EXPOSURE</div>
          <h2 className="atomic-section-title">APKLens vs Cloud Static Analyzers</h2>
          <p className="atomic-section-desc">
            Why security researchers and enterprises trust local in-browser inspection over legacy cloud services.
          </p>
        </div>

        <div className="compare-container">
          <div className="compare-table">
            {/* Header */}
            <div className="compare-header-row">
              <div className="compare-cell-feature">Capability</div>
              <div className="compare-cell-highlight">
                <div className="highlight-top-line"></div>
                <div className="col-badge">
                  <Shield size={14} className="text-emerald" />
                  <span>APKLens (Local)</span>
                </div>
              </div>
              <div className="compare-cell-dim">
                <div className="col-badge">
                  <span>Cloud Analyzers (MobSF/VirusTotal)</span>
                </div>
              </div>
            </div>

            {/* Rows */}
            <div className="compare-row">
              <div className="compare-cell-feature">100% Private (Runs on your device)</div>
              <div className="compare-cell-highlight">
                <Check size={20} className="text-emerald check-icon" />
              </div>
              <div className="compare-cell-dim">
                <span className="cross-icon">✕</span>
              </div>
            </div>

            <div className="compare-row">
              <div className="compare-cell-feature">Zero Binary Uploads to External Servers</div>
              <div className="compare-cell-highlight">
                <Check size={20} className="text-emerald check-icon" />
              </div>
              <div className="compare-cell-dim">
                <span className="cross-icon">✕</span>
              </div>
            </div>

            <div className="compare-row">
              <div className="compare-cell-feature">Safe for NDA & Pre-Release Binaries</div>
              <div className="compare-cell-highlight">
                <Check size={20} className="text-emerald check-icon" />
              </div>
              <div className="compare-cell-dim">
                <span className="cross-icon">✕</span>
              </div>
            </div>

            <div className="compare-row">
              <div className="compare-cell-feature">Free Forever & No Rate Limits</div>
              <div className="compare-cell-highlight">
                <Check size={20} className="text-emerald check-icon" />
              </div>
              <div className="compare-cell-dim">
                <span className="cross-icon">✕</span>
              </div>
            </div>

            <div className="compare-row">
              <div className="compare-cell-feature">Sub-Second Static Binary Triage</div>
              <div className="compare-cell-highlight">
                <Check size={20} className="text-emerald check-icon" />
              </div>
              <div className="compare-cell-dim">
                <span className="cross-icon">✕</span>
              </div>
            </div>

            <div className="compare-row">
              <div className="compare-cell-feature">OWASP Mobile Top 10 (2024 Release) Matrix</div>
              <div className="compare-cell-highlight">
                <Check size={20} className="text-emerald check-icon" />
              </div>
              <div className="compare-cell-dim">
                <span className="cross-icon">✕</span>
              </div>
            </div>

            <div className="compare-row">
              <div className="compare-cell-feature">Deep Link Scheme Hunter & ADB PoC Commands</div>
              <div className="compare-cell-highlight">
                <Check size={20} className="text-emerald check-icon" />
              </div>
              <div className="compare-cell-dim">
                <span className="cross-icon">✕</span>
              </div>
            </div>

            <div className="compare-row">
              <div className="compare-cell-feature">Works Fully Offline Without Internet</div>
              <div className="compare-cell-highlight">
                <Check size={20} className="text-emerald check-icon" />
              </div>
              <div className="compare-cell-dim">
                <span className="cross-icon">✕</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* How It Works (Styled like Atomic Chat's step grid with big watermark numbers) */}
      <section id="how-it-works" className="atomic-section">
        <div className="atomic-section-header">
          <div className="atomic-section-tag">WORKFLOW</div>
          <h2 className="atomic-section-title">How APKLens Works</h2>
          <p className="atomic-section-desc">
            Three simple steps to comprehensive Android static triage without complex command line toolchains.
          </p>
        </div>

        <div className="steps-grid">
          {/* Step 1 */}
          <div className="step-card">
            <div className="step-badge">01</div>
            <div className="step-content">
              <div className="step-icon-wrap">
                <Upload size={22} className="text-cyan" />
              </div>
              <h3 className="step-heading">Drop & In-Memory Unpack</h3>
              <p className="step-paragraph">
                The browser reads your APK directly into local memory as an ArrayBuffer. ZIP headers are unpacked without saving bytes to disk or transmitting to a remote backend.
              </p>
            </div>
            <div className="step-watermark">1</div>
          </div>

          {/* Step 2 */}
          <div className="step-card">
            <div className="step-badge">02</div>
            <div className="step-content">
              <div className="step-icon-wrap">
                <Zap size={22} className="text-indigo" />
              </div>
              <h3 className="step-heading">Automated Deep Triage</h3>
              <p className="step-paragraph">
                The binary AXML chunk parser decodes AndroidManifest.xml, maps Multi-DEX tables, extracts deep link schemes, and evaluates OWASP Mobile Top 10 compliance.
              </p>
            </div>
            <div className="step-watermark">2</div>
          </div>

          {/* Step 3 */}
          <div className="step-card">
            <div className="step-badge">03</div>
            <div className="step-content">
              <div className="step-icon-wrap">
                <FileText size={22} className="text-emerald" />
              </div>
              <h3 className="step-heading">Audit, Decompile & Export</h3>
              <p className="step-paragraph">
                Inspect Java/Kotlin source with targeted JADX decompilation, test deep link intent filters with ADB PoCs, and export Bug Bounty Markdown, SARIF, or CSV.
              </p>
            </div>
            <div className="step-watermark">3</div>
          </div>
        </div>
      </section>

      {/* Privacy Counter Stats (Styled exactly like Atomic Chat's pstats) */}
      <section className="atomic-privacy-section">
        <div className="privacy-inner">
          <div className="privacy-text-col">
            <div className="atomic-section-tag">GUARANTEED PRIVACY</div>
            <h2 className="privacy-title">
              No rate limits.<br />
              No subscriptions.<br />
              No cloud exposure.
            </h2>
            <p className="privacy-desc">
              Everything stays on your local machine. We don’t send your APK or findings anywhere, because there’s nowhere to send it. It all runs locally in your browser sandbox.
            </p>
          </div>

          <div className="privacy-stats-grid">
            <div className="pstat-box">
              <div className="pstat-val">0 bytes</div>
              <div className="pstat-lbl">of your APK bytecode or secrets ever leaves your device</div>
            </div>
            <div className="pstat-box">
              <div className="pstat-val">100%</div>
              <div className="pstat-lbl">client-side static analysis, works completely offline</div>
            </div>
            <div className="pstat-box">
              <div className="pstat-val inf-glyph">∞</div>
              <div className="pstat-lbl">APK audits, zero rate limits, no account required</div>
            </div>
          </div>
        </div>
      </section>

      {/* Developer Section */}
      <section id="developer" className="atomic-section">
        <div className="dev-card-atomic">
          <div className="dev-card-glow"></div>
          <div className="dev-card-inner">
            <div className="dev-top-row">
              <div className="dev-avatar-box">
                <img
                  src="/jojin.png"
                  alt="Jojin John"
                  className="dev-avatar-img"
                  width={64}
                  height={64}
                />
              </div>
              <div>
                <div className="dev-status-pill">
                  <span className="atomic-pulse-dot"></span>
                  <span>Software Engineer & Security Researcher</span>
                </div>
                <h3 className="dev-author-name">Jojin John</h3>
                <p className="dev-author-role">Creator & Core Architect of APKLens</p>
              </div>
            </div>

            <p className="dev-bio">
              Software Engineer and Ethical Hacker passionate about Android OS internals, Dalvik DEX bytecode reverse engineering, binary instrumentation, and designing high-performance developer tooling with zero server-side data leakage.
            </p>

            <div className="dev-links-atomic">
              <a
                href="https://www.linkedin.com/in/jojin-john/"
                target="_blank"
                rel="noopener noreferrer"
                className="atomic-btn-solid is-linkedin"
              >
                <Linkedin size={16} />
                <span>Connect on LinkedIn</span>
                <ArrowUpRight size={14} />
              </a>
              <a
                href="https://github.com/jojin1709"
                target="_blank"
                rel="noopener noreferrer"
                className="atomic-btn-outline"
              >
                <Github size={16} />
                <span>GitHub @jojin1709</span>
                <ArrowUpRight size={14} />
              </a>
              <a
                href="https://github.com/sponsors/jojin1709"
                target="_blank"
                rel="noopener noreferrer"
                className="atomic-btn-outline is-sponsor"
              >
                <Heart size={16} className="text-pink" />
                <span>Sponsor on GitHub</span>
                <ArrowUpRight size={14} />
              </a>
            </div>
          </div>
        </div>
      </section>

      {/* Bottom CTA Banner */}
      <section className="atomic-cta-banner">
        <div className="cta-banner-inner">
          <h2 className="cta-banner-title">Ready to inspect your Android APK?</h2>
          <p className="cta-banner-sub">
            Experience lightning-fast static triage, OWASP compliance scoring, and on-demand decompilation in seconds.
          </p>
          <button className="atomic-btn-solid is-large" onClick={onLaunch}>
            <span>Launch APKLens Console</span>
            <ArrowRight size={18} />
          </button>
        </div>
      </section>

      {/* Minimalist Atomic Footer */}
      <footer className="atomic-footer">
        <div className="footer-inner-atomic">
          <div className="footer-brand-atomic">
            <img src="/icon.svg" alt="APKLens" style={{ width: "20px", height: "20px" }} />
            <span className="footer-brand-title">APKLens</span>
            <span className="footer-brand-tag">• Privacy-First Android Security & Architecture Platform</span>
          </div>

          <div className="footer-nav-atomic">
            <a href="https://www.linkedin.com/in/jojin-john/" target="_blank" rel="noopener noreferrer" className="footer-link-atomic">
              <Linkedin size={14} /> LinkedIn
            </a>
            <a href="https://github.com/jojin1709" target="_blank" rel="noopener noreferrer" className="footer-link-atomic">
              <Github size={14} /> GitHub
            </a>
            <a href="https://github.com/sponsors/jojin1709" target="_blank" rel="noopener noreferrer" className="footer-link-atomic sponsor">
              <Heart size={14} /> Sponsor
            </a>
          </div>

          <div className="footer-copy-atomic">
            © 2026 JOJIN JOHN. Engineered for developers and security researchers worldwide.
          </div>
        </div>
      </footer>
    </div>
  );
}
