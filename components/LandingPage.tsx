"use client";

import React, { useState } from "react";
import {
  Shield, Lock, Zap, Code2, Cpu, FileText, CheckCircle2, ArrowRight,
  Upload, Layers, Eye, ShieldCheck, Check, Laptop, FileCode,
  Download, ArrowUpRight, Linkedin, Github, Heart
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
      {/* Dynamic Ambient Background Orbs */}
      <div className="ambient-bg">
        <div className="aurora-orb orb-1"></div>
        <div className="aurora-orb orb-2"></div>
        <div className="aurora-orb orb-3"></div>
        <div className="ambient-grid"></div>
      </div>

      {/* Top Navbar */}
      <nav className="landing-nav">
        <div className="landing-nav-inner">
          <div className="brand" onClick={onLaunch} style={{ cursor: "pointer" }}>
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

          <div className="landing-nav-links">
            <a href="#capabilities">Capabilities</a>
            <a href="#pipeline">Analysis Engine</a>
            <a href="#workflow">How It Works</a>
            <a href="#architecture">Privacy Architecture</a>
            <a href="#developer">Developer</a>
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
        <div className="hero-container">
          <div className="hero-badge">
            <span className="status-dot"></span>
            <span>100% In-Browser Inspection • Zero Server Uploads</span>
          </div>

          <h1 className="hero-title">
            The Modern Way to Inspect & Audit <br />
            <span className="gradient-text">Android APKs with Zero Data Exposure</span>
          </h1>

          <p className="hero-subtitle">
            APKLens decodes binary AndroidManifest.xml, inspects Dalvik bytecode,
            audits native ELF (.so) binaries, scans for hardcoded secrets, and decompiles
            source code—running 100% locally in your browser sandbox.
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
              input.accept = ".apk,application/vnd.android.package-archive";
              input.onchange = (e) => {
                const f = (e.target as HTMLInputElement).files?.[0];
                if (f) onFileSelect(f);
              };
              input.click();
            }}
          >
            <div className="dropzone-icon-box">
              <Upload size={30} />
            </div>
            <div className="dropzone-content">
              <h3>Drop your Android APK here or <span className="browse-link">browse files</span></h3>
              <p>Processed completely in local memory. Ideal for NDA & enterprise builds.</p>
            </div>
            <div className="dropzone-badges">
              <span className="dropzone-badge">
                <Lock size={13} /> Private Local Sandbox
              </span>
              <span className="format-pill">Split APKs</span>
              <span className="format-pill">Multi-DEX</span>
              <span className="format-pill">Native NDK</span>
            </div>
          </div>

          {/* Key Metrics Bar (Modern Cards) */}
          <div className="metrics-bar">
            <div className="metric-card">
              <div className="metric-card-top">
                <span className="metric-val">0 Bytes</span>
                <div className="metric-icon-wrap bg-indigo-glow">
                  <Lock size={16} />
                </div>
              </div>
              <span className="metric-label">Uploaded to external servers for static triage</span>
            </div>

            <div className="metric-card">
              <div className="metric-card-top">
                <span className="metric-val">Sub-Sec</span>
                <div className="metric-icon-wrap bg-blue-glow">
                  <Zap size={16} />
                </div>
              </div>
              <span className="metric-label">Binary AXML decode & permission extraction</span>
            </div>

            <div className="metric-card">
              <div className="metric-card-top">
                <span className="metric-val">JADX 1.5</span>
                <div className="metric-icon-wrap bg-purple-glow">
                  <Code2 size={16} />
                </div>
              </div>
              <span className="metric-label">On-demand Java & Kotlin AST source decompiler</span>
            </div>

            <div className="metric-card">
              <div className="metric-card-top">
                <span className="metric-val">SARIF 2.1</span>
                <div className="metric-icon-wrap bg-emerald-glow">
                  <FileText size={16} />
                </div>
              </div>
              <span className="metric-label">OASIS standard DevSecOps & PDF report export</span>
            </div>
          </div>
        </div>
      </section>

      {/* Ecosystem & Security Standards Compatibility Banner */}
      <section className="partner-strip">
        <div className="partner-title">Aligned with Industry Mobile Security & DevSecOps Standards</div>
        <div className="partner-logos">
          <div className="partner-item">
            <ShieldCheck size={18} className="partner-icon text-indigo" />
            <span className="partner-name">OWASP MASVS</span>
          </div>
          <div className="partner-item">
            <Code2 size={18} className="partner-icon text-cyan" />
            <span className="partner-name">JADX Engine</span>
          </div>
          <div className="partner-item">
            <FileCode size={18} className="partner-icon text-emerald" />
            <span className="partner-name">OASIS SARIF 2.1</span>
          </div>
          <div className="partner-item">
            <Cpu size={18} className="partner-icon text-purple" />
            <span className="partner-name">AOSP Standards</span>
          </div>
          <div className="partner-item">
            <Layers size={18} className="partner-icon text-blue" />
            <span className="partner-name">AndroidX</span>
          </div>
          <div className="partner-item">
            <CheckCircle2 size={18} className="partner-icon text-pink" />
            <span className="partner-name">DefectDojo</span>
          </div>
          <div className="partner-item">
            <Lock size={18} className="partner-icon text-amber" />
            <span className="partner-name">SonarQube SAST</span>
          </div>
        </div>
        <div className="partner-headline">
          13 In-Browser Static Inspection Engines
        </div>
      </section>

      {/* Analysis Engine Pipeline Section */}
      <section id="pipeline" className="showcase-section">
        <div className="window-mockup">
          <div className="window-titlebar">
            <div className="window-dots">
              <span className="window-dot dot-close"></span>
              <span className="window-dot dot-min"></span>
              <span className="window-dot dot-max"></span>
            </div>
            <div className="window-title">APKLens Client-Side Architecture Pipeline</div>
            <span className="window-badge">Real-Time Parsing Engine</span>
          </div>

          <div className="window-content">
            <div className="mock-grid">
              <div className="mock-stat">
                <span>Core Parsing</span>
                <b>Pure TypeScript</b>
              </div>
              <div className="mock-stat">
                <span>Security Engine</span>
                <b>Entropy & Patterns</b>
              </div>
              <div className="mock-stat">
                <span>Native Auditing</span>
                <b>ELF32 & ELF64</b>
              </div>
              <div className="mock-stat">
                <span>Compliance</span>
                <b>SARIF 2.1 & PDF</b>
              </div>
            </div>

            <div className="mock-preview-columns">
              <div className="mock-findings-box">
                <div className="mock-code-head">
                  <span>Client-Side Static Inspection Engines</span>
                  <span>100% In-Browser</span>
                </div>

                <div className="mock-finding-item">
                  <span className="finding-tag tag-critical">Engine</span>
                  <div>
                    <b>Binary AXML Chunk Decoder</b>
                    <p>Decodes compiled binary AndroidManifest.xml, extracting real package metadata, components, and permissions.</p>
                  </div>
                </div>

                <div className="mock-finding-item">
                  <span className="finding-tag tag-medium">Engine</span>
                  <div>
                    <b>Dalvik Bytecode & String Sweeper</b>
                    <p>Parses Multi-DEX header tables, class descriptor pools, methods, and embedded URL endpoints.</p>
                  </div>
                </div>

                <div className="mock-finding-item">
                  <span className="finding-tag tag-high">Engine</span>
                  <div>
                    <b>X.509 ASN.1 Certificate Validator</b>
                    <p>Extracts JAR v1 signatures and APK Signing Block v2/v3 certificates with validity and SHA-256 hashes.</p>
                  </div>
                </div>
              </div>

              <div className="mock-findings-box">
                <div className="mock-code-head">
                  <span>Automated SAST & DevSecOps Export</span>
                  <span>OASIS Aligned</span>
                </div>

                <div className="mock-finding-item">
                  <span className="finding-tag tag-critical">Security</span>
                  <div>
                    <b>Hardcoded Secret & Key Hunter</b>
                    <p>Pattern and Shannon entropy detection for exposed AWS keys, Google API tokens, Firebase databases, and Stripe keys.</p>
                  </div>
                </div>

                <div className="mock-finding-item">
                  <span className="finding-tag tag-medium">Native</span>
                  <div>
                    <b>ELF (.so) Shared Object Inspector</b>
                    <p>Identifies ARM, ARM64, x86 architectures, endianness, linked dependencies, and exported JNI functions.</p>
                  </div>
                </div>

                <div className="mock-finding-item">
                  <span className="finding-tag tag-high">Export</span>
                  <div>
                    <b>DevSecOps SARIF 2.1.0 & Executive PDF</b>
                    <p>One-click standard reports for GitHub Code Scanning, GitLab CI/CD, and printable PDF audits.</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Core Capabilities Grid */}
      <section id="capabilities" className="section-container">
        <div className="section-head">
          <div className="section-tag">CAPABILITIES</div>
          <h2 className="section-title">Engineered for Developers & Security Analysts</h2>
          <p className="section-desc">
            A complete suite of static inspection utilities that run inside your browser
            without installing command-line tools or bloated virtual environments.
          </p>
        </div>

        <div className="features-grid">
          {/* Feature 1 */}
          <div className="feature-glass-card">
            <div className="feature-icon bg-indigo-glow">
              <Lock size={24} />
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
            <div className="feature-icon bg-purple-glow">
              <Code2 size={24} />
            </div>
            <h3>On-Demand JADX Decompilation</h3>
            <p>
              Inspect thousands of compiled Dalvik bytecode classes. Click on any class to trigger
              focused, single-class AST decompilation with real-time percentage progress tracking
              and syntax highlighting.
            </p>
            <div className="feature-tags">
              <span>Single-Class AST</span>
              <span>Progress Tracking</span>
              <span>Java & Kotlin</span>
            </div>
          </div>

          {/* Feature 3 */}
          <div className="feature-glass-card">
            <div className="feature-icon bg-rose-glow">
              <Eye size={24} />
            </div>
            <h3>Automated Vulnerability & Secret Hunter</h3>
            <p>
              Scans bytecode strings and manifest configurations for exposed AWS access keys,
              Google API keys, Firebase real-time databases, Stripe secrets, private keys, and
              weak encryption ciphers (ECB, DES, MD5).
            </p>
            <div className="feature-tags">
              <span>Entropy & Patterns</span>
              <span>Masked Findings</span>
              <span>OWASP Aligned</span>
            </div>
          </div>

          {/* Feature 4 */}
          <div className="feature-glass-card">
            <div className="feature-icon bg-emerald-glow">
              <Cpu size={24} />
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
              <FileText size={24} />
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
              <span>Security Score</span>
            </div>
          </div>

          {/* Feature 6 */}
          <div className="feature-glass-card">
            <div className="feature-icon bg-blue-glow">
              <Layers size={24} />
            </div>
            <h3>IndexedDB Offline Workspace</h3>
            <p>
              Your analyses are automatically preserved in your browser&apos;s encrypted IndexedDB storage.
              Switch between previous analyses, compare security findings, and resume work anytime
              without re-uploading.
            </p>
            <div className="feature-tags">
              <span>Local Storage</span>
              <span>IndexedDB Vault</span>
              <span>Instant Reload</span>
            </div>
          </div>
        </div>
      </section>

      {/* 3-Step Workflow Section */}
      <section id="workflow" className="workflow-section">
        <div className="section-head">
          <div className="section-tag">WORKFLOW</div>
          <h2 className="section-title">How APKLens Works</h2>
          <p className="section-desc">
            Streamlined static triage designed for velocity and privacy.
          </p>
        </div>

        <div className="workflow-grid">
          <div className="workflow-card">
            <span className="step-num">01</span>
            <h3>Drop & In-Memory Decompression</h3>
            <p>
              The browser reads your APK as an ArrayBuffer using the File API. The archive entries
              are parsed locally without touching server disk or transmitting bytes.
            </p>
          </div>

          <div className="workflow-card">
            <span className="step-num">02</span>
            <h3>Static Binary & Bytecode Triage</h3>
            <p>
              The binary AXML chunk parser decodes AndroidManifest.xml. Dalvik DEX headers are mapped,
              native ELF architectures inspected, and secrets swept using regex & entropy rules.
            </p>
          </div>

          <div className="workflow-card">
            <span className="step-num">03</span>
            <h3>Explore, Decompile & Export</h3>
            <p>
              Browse classes, decompile targeted methods to readable Java/Kotlin via JADX, and
              export audit-ready SARIF 2.1.0 or printable executive PDF reports.
            </p>
          </div>
        </div>
      </section>

      {/* Architecture Showcase */}
      <section id="architecture" className="section-container">
        <div className="arch-card">
          <div className="arch-header">
            <div>
              <div className="section-tag">ZERO DATA LEAKAGE</div>
              <h2>How APKLens Protects Confidential Binaries</h2>
            </div>
            <button className="glow-btn" onClick={onLaunch}>
              <span>Open Console</span>
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
                <li>❌ Proprietary intellectual property, API keys, and pre-release code exposed.</li>
                <li>❌ High latency queues and multi-minute waits for analysis.</li>
                <li>❌ Requires user account registration, credit cards, or subscription tiers.</li>
              </ul>
            </div>

            <div className="arch-column modern">
              <div className="arch-column-head">
                <span className="dot-green"></span>
                <b>APKLens Privacy-First Architecture</b>
              </div>
              <ul className="arch-list">
                <li>✅ <b>100% In-Browser Static Engine:</b> Binary parsing runs in local JavaScript memory.</li>
                <li>✅ <b>Targeted On-Demand Decompilation:</b> Only target classes are requested.</li>
                <li>✅ <b>Zero Account Friction:</b> No sign-in, no tracking cookies, no telemetry logs.</li>
                <li>✅ <b>Instant Feedback:</b> Sub-second analysis of manifest, certs, and DEX headers.</li>
              </ul>
            </div>
          </div>
        </div>
      </section>

      {/* Developer & Security Researcher Section */}
      <section id="developer" className="section-container">
        <div className="dev-card">
          <div className="dev-glow"></div>
          <div className="dev-inner">
            <div className="dev-header">
              <div className="dev-avatar-wrap">
                <div className="dev-avatar">
                  <Shield size={32} className="text-indigo" />
                </div>
                <div className="dev-status-badge">
                  <span className="dot-green"></span> Security Researcher & Dev
                </div>
              </div>
              <div className="dev-title-block">
                <div className="section-tag">ARCHITECT & SECURITY RESEARCHER</div>
                <h2 className="dev-name">Jojin John</h2>
                <p className="dev-role">Software Engineer & Ethical Hacker / Security Researcher</p>
              </div>
            </div>

            <p className="dev-description">
              Creator and core developer of <b>APKLens</b>. Passionate about Android operating system internals,
              Dalvik bytecode analysis, binary reverse engineering, and architecting privacy-first security tooling
              that eliminates server-side data leakage.
            </p>

            <div className="dev-links-row">
              <a
                href="https://www.linkedin.com/in/jojin-john/"
                target="_blank"
                rel="noopener noreferrer"
                className="dev-btn linkedin"
              >
                <Linkedin size={16} />
                <span>Connect on LinkedIn</span>
                <ArrowUpRight size={14} />
              </a>
              <a
                href="https://github.com/jojin1709"
                target="_blank"
                rel="noopener noreferrer"
                className="dev-btn github"
              >
                <Github size={16} />
                <span>GitHub @jojin1709</span>
                <ArrowUpRight size={14} />
              </a>
              <a
                href="https://github.com/sponsors/jojin1709"
                target="_blank"
                rel="noopener noreferrer"
                className="dev-btn sponsor"
              >
                <Heart size={16} />
                <span>Sponsor on GitHub</span>
                <ArrowUpRight size={14} />
              </a>
            </div>
          </div>
        </div>
      </section>

      {/* Call To Action Banner */}
      <section className="cta-banner">
        <div className="cta-inner">
          <h2>Ready to Inspect Your First Android APK?</h2>
          <p>
            Experience lightning-fast client-side static analysis with automated security
            audits and on-demand source decompilation.
          </p>
          <div className="cta-actions">
            <button className="glow-btn big" onClick={onLaunch}>
              <span>Launch APKLens Console</span>
              <ArrowRight size={18} />
            </button>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="landing-footer">
        <div className="footer-inner">
          <div className="footer-brand">
            <img src="/icon.svg" alt="APKLens" style={{ width: "20px", height: "20px" }} />
            <b>APKLens</b>
            <span>• Next-Gen Android Security & Architecture Platform</span>
          </div>
          <div className="footer-links-list">
            <a href="https://www.linkedin.com/in/jojin-john/" target="_blank" rel="noopener noreferrer" className="footer-link">
              <Linkedin size={14} /> LinkedIn
            </a>
            <a href="https://github.com/jojin1709" target="_blank" rel="noopener noreferrer" className="footer-link">
              <Github size={14} /> GitHub
            </a>
            <a href="https://github.com/sponsors/jojin1709" target="_blank" rel="noopener noreferrer" className="footer-link sponsor-highlight">
              <Heart size={14} /> Sponsor on GitHub
            </a>
          </div>
          <div className="footer-copy">
            © 2026 JOJIN JOHN. All Rights Reserved.
          </div>
        </div>
      </footer>
    </div>
  );
}
