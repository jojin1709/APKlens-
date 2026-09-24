"use client";

import React, { useState } from "react";
import {
  Shield, Lock, Zap, Code2, Cpu, FileText, CheckCircle2, ArrowRight,
  Upload, Terminal, Search, ExternalLink, Check, Sparkles, Layers, Eye
} from "lucide-react";

interface LandingPageProps {
  onLaunch: () => void;
  onFileSelect: (file: File) => void;
}

export default function LandingPage({ onLaunch, onFileSelect }: LandingPageProps) {
  const [dragActive, setDragActive] = useState(false);

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragActive(false);
    if (e.dataTransfer.files?.[0]) {
      const file = e.dataTransfer.files[0];
      if (file.name.toLowerCase().endsWith(".apk")) {
        onFileSelect(file);
      }
    }
  };

  return (
    <div className="landing-wrap">
      {/* Top Navbar */}
      <nav className="landing-nav">
        <div className="landing-nav-inner">
          <div className="brand" onClick={onLaunch} style={{ cursor: "pointer" }}>
            <div className="brandmark">
              <Shield size={22} className="brandmark-icon" />
            </div>
            <div>
              <div className="brand-title">
                APKLens <span className="version-pill">v2.0 PRO</span>
              </div>
              <span className="brand-sub">Android Binary Intelligence & SAST</span>
            </div>
          </div>

          <div className="landing-nav-links">
            <a href="#capabilities">Capabilities</a>
            <a href="#architecture">Architecture</a>
            <a href="#sast">SAST Scanner</a>
            <a href="#reports">SARIF & Reports</a>
          </div>

          <div className="landing-nav-actions">
            <button className="glow-btn" onClick={onLaunch}>
              <span>Launch Console</span>
              <ArrowRight size={15} />
            </button>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="hero-section">
        <div className="hero-bg-glow"></div>
        <div className="hero-container">
          <div className="hero-badge">
            <Sparkles size={14} className="text-cyan" />
            <span>Privacy-First • 100% In-Browser Parsing • Zero Cloud Leakage</span>
          </div>

          <h1 className="hero-title">
            Reverse Engineer & Audit <br />
            <span className="gradient-text">Android APKs with Zero Data Exposure</span>
          </h1>

          <p className="hero-subtitle">
            APKLens extracts binary AndroidManifest.xml, inspects Dalvik bytecode,
            hunts hardcoded API secrets, audits native ELF (.so) binaries, and reconstructs
            Java/Kotlin source code on-demand.
          </p>

          {/* Interactive Drag & Drop Box */}
          <div
            className={`hero-dropzone ${dragActive ? "drag-over" : ""}`}
            onDragOver={(e) => { e.preventDefault(); setDragActive(true); }}
            onDragLeave={() => setDragActive(false)}
            onDrop={handleDrop}
            onClick={() => {
              const input = document.createElement("input");
              input.type = "file";
              input.accept = ".apk";
              input.onchange = (e) => {
                const f = (e.target as HTMLInputElement).files?.[0];
                if (f) onFileSelect(f);
              };
              input.click();
            }}
          >
            <div className="dropzone-icon-box">
              <Upload size={28} className="dropzone-icon" />
            </div>
            <div className="dropzone-content">
              <h3>Drop your Android APK here or <span className="text-cyan">browse files</span></h3>
              <p>Supports .apk (Split APKs, Multi-DEX, Native NDK). Analyzed instantly in memory.</p>
            </div>
            <div className="dropzone-badge">
              <Lock size={13} /> Local-First Security Sandbox
            </div>
          </div>

          {/* Quick Metrics Bar */}
          <div className="metrics-bar">
            <div className="metric-item">
              <span className="metric-val text-cyan">0 Bytes</span>
              <span className="metric-label">Uploaded to Cloud for Static Analysis</span>
            </div>
            <div className="metric-divider"></div>
            <div className="metric-item">
              <span className="metric-val text-indigo">JADX 1.5.1</span>
              <span className="metric-label">Cloud AST Decompiler Engine</span>
            </div>
            <div className="metric-divider"></div>
            <div className="metric-item">
              <span className="metric-val text-emerald">SARIF 2.1.0</span>
              <span className="metric-label">OASIS Standard DevSecOps Export</span>
            </div>
            <div className="metric-divider"></div>
            <div className="metric-item">
              <span className="metric-val text-amber">OWASP MASTG</span>
              <span className="metric-label">Aligned Vulnerability Checks</span>
            </div>
          </div>
        </div>
      </section>

      {/* Core Capabilities Grid */}
      <section id="capabilities" className="section-container">
        <div className="section-head">
          <div className="section-tag">CAPABILITIES</div>
          <h2 className="section-title">Engineered for Elite Security Researchers & Developers</h2>
          <p className="section-desc">
            A complete suite of static reverse engineering tools that run in your browser without
            installing bloated command-line utilities.
          </p>
        </div>

        <div className="features-grid">
          {/* Feature 1 */}
          <div className="feature-glass-card">
            <div className="feature-icon bg-cyan-glow">
              <Lock size={22} className="text-cyan" />
            </div>
            <h3>100% Client-Side Binary Engine</h3>
            <p>
              Decode compiled binary AXML (<code className="tag-code">AndroidManifest.xml</code>),
              read chunk headers, extract permissions, activities, receivers, and parse v1/v2/v3
              X.509 signatures without sending your APK to external servers.
            </p>
            <div className="feature-tags">
              <span>Pure TypeScript</span>
              <span>Chunk Parser</span>
              <span>X.509 Validator</span>
            </div>
          </div>

          {/* Feature 2 */}
          <div className="feature-glass-card">
            <div className="feature-icon bg-indigo-glow">
              <Code2 size={22} className="text-indigo" />
            </div>
            <h3>On-Demand JADX Cloud Decompilation</h3>
            <p>
              Inspect thousands of compiled Dalvik bytecode classes. Click on any class to trigger
              focused, single-class AST decompilation with real-time percentage progress tracking
              and syntax highlighting.
            </p>
            <div className="feature-tags">
              <span>FastAPI Backend</span>
              <span>Single-Class AST</span>
              <span>Real-Time Progress</span>
            </div>
          </div>

          {/* Feature 3 */}
          <div className="feature-glass-card">
            <div className="feature-icon bg-rose-glow">
              <Eye size={22} className="text-rose" />
            </div>
            <h3>Automated SAST & Credential Hunter</h3>
            <p>
              Scans bytecode strings and manifest configurations for exposed AWS access keys,
              Google API keys, Firebase real-time databases, Stripe secrets, private keys, and
              weak encryption ciphers (ECB, DES, MD5).
            </p>
            <div className="feature-tags">
              <span>Entropy & Regex</span>
              <span>Masked Findings</span>
              <span>OWASP Aligned</span>
            </div>
          </div>

          {/* Feature 4 */}
          <div className="feature-glass-card">
            <div className="feature-icon bg-emerald-glow">
              <Cpu size={22} className="text-emerald" />
            </div>
            <h3>ELF (.so) Native Symbol Inspector</h3>
            <p>
              Audits compiled C/C++ native shared libraries in <code className="tag-code">lib/</code>.
              Identifies machine architectures (ARMv7, ARM64, x86_64), endianness, linked shared
              libraries, and exported JNI functions (<code className="tag-code">Java_*</code>, <code className="tag-code">JNI_OnLoad</code>).
            </p>
            <div className="feature-tags">
              <span>ELF32 / ELF64</span>
              <span>JNI Table</span>
              <span>Dynamic Imports</span>
            </div>
          </div>

          {/* Feature 5 */}
          <div className="feature-glass-card">
            <div className="feature-icon bg-amber-glow">
              <FileText size={22} className="text-amber" />
            </div>
            <h3>Executive Reports & SARIF 2.1.0</h3>
            <p>
              Generate compliance-ready assessment reports. Export OASIS standard SARIF 2.1.0
              directly into GitHub Code Scanning or GitLab CI/CD, and print professional executive
              PDF reports with a calculated security score.
            </p>
            <div className="feature-tags">
              <span>SARIF 2.1.0</span>
              <span>Printable PDF</span>
              <span>Score Benchmark</span>
            </div>
          </div>

          {/* Feature 6 */}
          <div className="feature-glass-card">
            <div className="feature-icon bg-cyan-glow">
              <Layers size={22} className="text-cyan" />
            </div>
            <h3>IndexedDB Offline Workspace</h3>
            <p>
              Your analyses are automatically preserved in your browser's encrypted IndexedDB storage.
              Switch between previous analyses, compare security findings, and resume work anytime
              without re-uploading.
            </p>
            <div className="feature-tags">
              <span>Zero-Storage Server</span>
              <span>Local IndexedDB</span>
              <span>Instant Reload</span>
            </div>
          </div>
        </div>
      </section>

      {/* Architecture Showcase */}
      <section id="architecture" className="section-container">
        <div className="arch-card">
          <div className="arch-header">
            <div>
              <div className="section-tag">ZERO DATA LEAKAGE</div>
              <h2>How APKLens Protects Your Intellectual Property</h2>
            </div>
            <button className="glow-btn" onClick={onLaunch}>
              <span>Try Live in Console</span>
              <ArrowRight size={15} />
            </button>
          </div>

          <div className="arch-comparison-grid">
            <div className="arch-column legacy">
              <div className="arch-column-head">
                <span className="dot-red"></span>
                <b>Traditional Cloud Analyzers (e.g. VirusTotal, MobSF Cloud)</b>
              </div>
              <ul className="arch-list">
                <li>❌ Entire APK file uploaded and stored on third-party servers.</li>
                <li>❌ Proprietary intellectual property, API keys, and pre-release code leaked.</li>
                <li>❌ Slow queue times and multi-minute waits for analysis.</li>
                <li>❌ Requires user account registration and credit-card billing.</li>
              </ul>
            </div>

            <div className="arch-column modern">
              <div className="arch-column-head">
                <span className="dot-green"></span>
                <b>APKLens Privacy-First Architecture</b>
              </div>
              <ul className="arch-list">
                <li>✅ <b>100% In-Browser Static Engine:</b> Binary parsing runs in local JS memory.</li>
                <li>✅ <b>Targeted On-Demand Decompilation:</b> Only target classes are requested.</li>
                <li>✅ <b>Zero Account Friction:</b> No sign-in, no tracking cookies, no server logs.</li>
                <li>✅ <b>Instant Feedback:</b> Sub-second analysis of manifest, certs, and DEX headers.</li>
              </ul>
            </div>
          </div>
        </div>
      </section>

      {/* Call To Action Footer Banner */}
      <section className="cta-banner">
        <div className="cta-inner">
          <h2>Ready to Inspect Your First Android APK?</h2>
          <p>
            Experience lightning-fast client-side static reverse engineering with automated SAST
            security audits and on-demand JADX cloud decompilation.
          </p>
          <div className="cta-actions">
            <button className="glow-btn big" onClick={onLaunch}>
              <span>Open APKLens Console</span>
              <ArrowRight size={18} />
            </button>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="landing-footer">
        <div className="footer-inner">
          <div className="footer-brand">
            <Shield size={18} className="text-cyan" />
            <b>APKLens</b>
            <span>• Next-Gen Android Binary Inspection Platform</span>
          </div>
          <div className="footer-copy">
            © 2026 JOJIN JOHN. All Rights Reserved. APKLens Proprietary Platform.
          </div>
        </div>
      </footer>
    </div>
  );
}
