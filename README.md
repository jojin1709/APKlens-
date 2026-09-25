<div align="center">

<a href="https://apklens-in.vercel.app/">
  <img src="public/icon.png" width="128" height="128" alt="APKLens Logo" />
</a>

# APKLens

### Autonomous, Privacy-First Browser-Based Android APK Inspector & Security Suite

**100% In-Browser Analysis** — binary AndroidManifest.xml decoding, Dalvik DEX bytecode inspection,
X.509 certificate parsing, and automated vulnerability scanning with zero server uploads and zero data leakage.

**Built for** Android developers · security researchers · QA engineers who want instant APK triage — running **100% locally in your browser sandbox**.

<br/>

[![License](https://img.shields.io/github/license/jojin1709/APKlens-?style=flat-square&labelColor=0D1117&color=3DDC84)](LICENSE)
[![Next.js](https://img.shields.io/badge/Next.js-15-0D1117?style=flat-square&labelColor=0D1117&logo=next.js&logoColor=3DDC84)](https://nextjs.org/)
[![React](https://img.shields.io/badge/React-19-0D1117?style=flat-square&labelColor=0D1117&logo=react&logoColor=3DDC84)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-0D1117?style=flat-square&labelColor=0D1117&logo=typescript&logoColor=3DDC84)](https://www.typescriptlang.org/)
[![Stars](https://img.shields.io/github/stars/jojin1709/APKlens-?style=flat-square&labelColor=0D1117&color=3DDC84)](https://github.com/jojin1709/APKlens-/stargazers)
[![Forks](https://img.shields.io/github/forks/jojin1709/APKlens-?style=flat-square&labelColor=0D1117&color=3DDC84)](https://github.com/jojin1709/APKlens-/network/members)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Jojin_John-0A66C2?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/jojin-john/)
[![Last Commit](https://img.shields.io/github/last-commit/jojin1709/APKlens-?style=flat-square&labelColor=0D1117&color=3DDC84)](https://github.com/jojin1709/APKlens-/commits/main)

<br/>

![](https://img.shields.io/badge/21_Analysis_Modules-3DDC84?style=for-the-badge&labelColor=0D1117)
&nbsp;![](https://img.shields.io/badge/100%25_Client_Side-3DDC84?style=for-the-badge&labelColor=0D1117&logo=googlechrome&logoColor=white)
&nbsp;![](https://img.shields.io/badge/Frida_%2B_Intent_Playground-3DDC84?style=for-the-badge&labelColor=0D1117&logo=terminal&logoColor=white)
&nbsp;![](https://img.shields.io/badge/Binary_AXML_Decoder-3DDC84?style=for-the-badge&labelColor=0D1117&logo=android&logoColor=white)
&nbsp;![](https://img.shields.io/badge/Exodus_Trackers-3DDC84?style=for-the-badge&labelColor=0D1117)
&nbsp;![](https://img.shields.io/badge/SARIF_2.1.0_%2B_CI-3DDC84?style=for-the-badge&labelColor=0D1117&logo=githubactions&logoColor=white)
&nbsp;![](https://img.shields.io/badge/PWA_Offline_Ready-3DDC84?style=for-the-badge&labelColor=0D1117)

<br/>

<a href="https://apklens-in.vercel.app/"><img src="https://img.shields.io/badge/Launch_Live_App-3DDC84?style=for-the-badge&logo=vercel&logoColor=black" alt="Launch Live App"></a>&nbsp;
<a href="#why-apklens"><img src="https://img.shields.io/badge/Why_APKLens-30363D?style=for-the-badge&logoColor=white" alt="Why APKLens"></a>&nbsp;
<a href="#analysis-modules"><img src="https://img.shields.io/badge/Modules-30363D?style=for-the-badge&logoColor=white" alt="Modules"></a>&nbsp;
<a href="#architecture--how-it-works"><img src="https://img.shields.io/badge/Architecture-30363D?style=for-the-badge&logo=github&logoColor=white" alt="Architecture"></a>&nbsp;
<a href="#honest-scope"><img src="https://img.shields.io/badge/Honest_Scope-30363D?style=for-the-badge&logoColor=white" alt="Honest Scope"></a>

</div>

---

## Contents

- [Why APKLens](#why-apklens)
- [Analysis Modules](#analysis-modules)
- [Key Capabilities](#key-capabilities)
- [Architecture & How It Works](#architecture--how-it-works)
- [How to Use](#how-to-use)
- [Honest Scope & Privacy Architecture](#honest-scope)
- [Contributing](#contributing)
- [License](#license)
- [Support](#support)

---

## Why APKLens

- **100% Client-Side Privacy Sandbox** — your .apk binary is unpacked and analyzed entirely inside your browser's local memory via Web Crypto, FileReader, and JSZip. Zero megabytes of your proprietary code are ever sent to external cloud servers.
- **Native Binary AXML & Network Security Config Decoder** — decodes compiled binary AndroidManifest.xml and res/xml/network_security_config.xml files directly in TypeScript with sub-second performance.
- **Automated SAST & Insecure Cryptography Hunter** — sweeps bytecode strings for exposed AWS tokens, Google Cloud API keys, Firebase URLs, Stripe keys, AES/ECB weak modes, and static IVs.
- **Exodus Privacy Tracker Detector** — identifies tracking and analytics SDKs (Google AdMob, AppsFlyer, Facebook, Adjust, Mixpanel) against the Exodus catalog.
- **Pentester Toolkit (1-Click Frida & ADB Exploit Assistant)** — auto-generates copy-paste Frida bypass scripts (SSL pinning, Burp CA re-pinning, anti-root) and ready-to-run ADB shell execution commands for all exported components.
- **Pure In-Browser Smali Disassembler** — disassembles DEX bytecodes directly in browser TypeScript without requiring an external backend.
- **Compliance-Ready Reporting & Headless CI/CD** — export OASIS SARIF 2.1.0 reports for GitHub Code Scanning / GitLab DevSecOps pipelines, run headless CI scans (`scripts/apklens-ci.mjs`), plus printable PDF reports.
- **Encrypted IndexedDB Session Vault & Version Diff** — compare two APK versions side-by-side to track newly added permissions, exported components, and findings.

---

## Analysis Modules

| # | Module | What it does |
|:---:|---|---|
| 1 | **Overview** | App metadata, package name, version, SDK levels, SHA-256 hash, security score ring, high-priority vulnerability cards |
| 2 | **File Explorer** | Searchable in-memory archive directory tree showing every asset, binary, and resource with raw byte sizes |
| 3 | **AndroidManifest** | IDE-style XML viewer with syntax highlighting, line numbers, copy-to-clipboard — decoded from binary AXML format |
| 4 | **Permissions** | Comprehensive audit of declared vs. dangerous Android permissions with protection level indicators |
| 5 | **Components** | Analysis of exported vs. private Activities, Services, Broadcast Receivers, and Content Providers |
| 6 | **Deep Links & Schemes** | Audit of all browsable URI schemes and deep link intent filters declared in AndroidManifest.xml |
| 7 | **DEX & Decompiler** | Dalvik class catalog, method metrics, string pools, live Smali opcode disassembler, and JADX source decompilation |
| 8 | **Native Libraries (.so)** | ELF32/ELF64 architecture inspection, endianness, linked shared objects, exported JNI entry points, and compiler hardening audit (PIE, Stack Canary, NX Stack, RELRO, FORTIFY, RPATH) |
| 9 | **Resources** | Visual catalog of application layouts, values, drawables, and compiled resource references |
| 10 | **Network & URLs** | Extracted HTTP/HTTPS endpoints, domain names, WebViews, and deep Network Security Config audit |
| 11 | **Security & Secrets** | Hardcoded credential scanner (AWS, Google, Firebase, Stripe), weak ciphers, and storage/backup audit |
| 12 | **Trackers & Privacy** | Exodus Privacy signature engine matching advertising, telemetry, and tracking SDK footprints |
| 13 | **Frida Hook Generator** | 1-click tailored dynamic instrumentation scripts (SSL unpinning, Burp CA re-pinning, anti-root, cipher logger) |
| 14 | **ADB Exploit Assistant** | Dedicated interactive drawer with ready-to-run adb commands for all exported components and backup dumps |
| 15 | **Intent Playground** | Interactive Intent Spoofing & Injection workbench with custom extras (--es, --ez, --ei), flags, and export to ADB, Python, Frida, and Bash |
| 16 | **OWASP Mobile Top 10** | Automated mapping of findings to official 2024 OWASP Mobile Top 10 (MASVS) risk categories |
| 17 | **Bytecode Strings** | Live string pool sweeper across all DEX headers with instant filtering and clipboard copying |
| 18 | **Certificate & Signing** | Extraction of v1/v2/v3 X.509 certs, validity dates, issuer DNs, and SHA-256 fingerprints |
| 19 | **Technology Stack** | Fingerprinting of frameworks and SDKs (Jetpack, Flutter, React Native, Unity, OkHttp, Firebase) |
| 20 | **APK Version Diff** | Side-by-side regression analysis comparing permissions, components, secrets, and size between two APK builds |
| 21 | **Reports & Exports** | One-click JSON dumps, OASIS SARIF 2.1.0 exports, and printable executive PDF reports |

---

## Key Capabilities

- **Pure TypeScript AXML Engine:** Binary XML chunk parsing without requiring Android SDK tools (aapt, apkanalyzer, or apktool).
- **Universal Archive Support:** Ingests standard `.apk`, Google Play `.aab` (Android App Bundle), `.xapk`, and `.apks` split packages seamlessly.
- **ELF Binary Hardening Auditor:** Pure client-side parsing of ELF program headers and string tables to detect PIE, Stack Canary (`__stack_chk_fail`), NX Stack (`PT_GNU_STACK`), RELRO (`PT_GNU_RELRO`), `FORTIFY_SOURCE`, and insecure RPATH/RUNPATH references.
- **Interactive Intent Injection Playground:** Real-time IPC attack surface testing with custom action, data URI, MIME, category, flag, and extra parameter crafting, exported directly as ADB shell commands, Python subprocess scripts, Frida hooks, or Bash scripts.
- **X.509 Certificate Extractor:** Parses ASN.1 DER blocks from META-INF/*.RSA and APK Signing Block structures.
- **Multi-DEX Bytecode Sweeper:** Recursively parses classes.dex, classes2.dex, ... identifying class descriptors, method counts, and printable string tables.
- **Entropy & Regex Secret Engine:** Shannon entropy and targeted regex signatures to detect accidentally committed tokens and API keys.
- **Premium Atomic Black UI:** Sleek dark Atomic Black aesthetic (#08080a), Android green (#3DDC84) accents, fixed sidebar navigator, and a premium APK scan loading experience.

---

## Architecture & How It Works

```mermaid
flowchart TB
    subgraph Client ["Client-Side Browser Sandbox (100% Private)"]
        APK["User APK File"] --> Reader["Browser File API / ArrayBuffer"]
        Reader --> SHA["Web Crypto SHA-256 Fingerprint"]
        Reader --> Unpack["JSZip In-Memory Stream Unpacker"]

        subgraph Decoders ["Static Analysis Pipeline"]
            Unpack --> AXML["Binary AXML Parser<br/>AndroidManifest.xml"]
            Unpack --> DEX["Dalvik DEX Inspector<br/>Multi-DEX Classes & Methods"]
            Unpack --> CERT["ASN.1 Certificate Engine<br/>v1 / v2 / v3 Signatures"]
            Unpack --> ELF["ELF Native Library Auditor<br/>.so Dynamic Symbols & JNI"]

            DEX --> STR["Bytecode String & Secret Hunter<br/>AWS, GCP, Firebase, Entropy"]
            DEX --> TECH["Technology Fingerprinter<br/>Flutter, React Native, Jetpack"]
            AXML --> COMP["Component & Permission Auditor<br/>Activities, Services, Providers"]
            AXML --> DEEP["Deep Links & Browsable Schemes"]
        end

        subgraph Engine ["APKLens Reactive Core"]
            SHA --> Core["Reactive State & Scoring Engine"]
            COMP --> Core
            DEEP --> Core
            STR --> Core
            TECH --> Core
            CERT --> Core
            ELF --> Core
            Core --> OWASP["OWASP Mobile Top 10 Risk Mapper"]
        end

        subgraph Presentation ["Presentation & Persistence"]
            Core --> UI["15-Module Dark Glassmorphism UI"]
            Core --> Vault["IndexedDB Local Session Vault"]
            Core --> Reports["OASIS SARIF 2.1.0 & Executive PDF Reports"]
        end
    end

    subgraph Backend ["Isolated Cloud Container (Optional)"]
        DEX -.->|"On-Demand Single Class"| JADX["JADX Decompiler API<br/>Fast C1 JIT Engine"]
        JADX -.->|"Java / Kotlin AST Source"| UI
    end

    classDef primary fill:#08080a,stroke:#3DDC84,stroke-width:2px,color:#fff
    classDef secondary fill:#121217,stroke:#27272a,stroke-width:1px,color:#e4e4e7
    classDef accent fill:#112419,stroke:#3DDC84,stroke-width:1.5px,color:#3DDC84

    class APK,Core,UI,JADX primary
    class Reader,SHA,Unpack,Vault,Reports secondary
    class AXML,DEX,CERT,ELF,STR,TECH,COMP,DEEP,OWASP accent
```

---

## How to Use

1. Open **https://apklens-in.vercel.app/** in any modern browser (Chrome, Edge, Firefox, Safari).
2. Drag and drop any .apk file into the upload zone, or click **Analyze New APK** to browse for a file.
3. Switch through the 15 analysis tabs to inspect every aspect of the APK.
4. Export your report via **JSON**, **OASIS SARIF 2.1.0**, or **Printable Executive PDF**.

---

## Honest Scope

| Feature | What it really does |
|---|---|
| **Static Analysis** | 100% Client-Side. APK is unpacked in browser RAM; no file content is sent to third-party servers. |
| **AXML Decoding** | Decodes binary XML chunks into valid XML in pure TypeScript. |
| **JADX Decompilation** | Target classes are processed via the JADX decompiler service. |
| **X.509 Verification** | Extracts and decodes X.509 signing certificates from the APK signing block and META-INF. |
| **Secret Detection** | Pattern & entropy-based regex scanner. Flags high-probability matches for manual verification. |
| **Storage & Privacy** | Scan history stored locally in your browser IndexedDB. No tracking, no accounts, no telemetry. |

---

## Contributing

**Fork it -> improve it -> test it -> open a PR.**

Before opening a pull request:
1. Run 
pm run build — ensure zero TypeScript or Next.js build errors.
2. Run 
pm run lint — verify code quality.
3. Preserve the privacy-first guarantee: all static parsing must remain 100% client-side.

---

## License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for full details.

Copyright (c) 2026 **JOJIN JOHN**.

---

## Support

Free and open-source. If APKLens saves you time, star the repo — it helps others discover the project.

<div align="center">

### Sponsor jojin1709

<a href="https://github.com/sponsors/jojin1709"><img src="https://img.shields.io/badge/GitHub_Sponsors-EA4AAA?style=for-the-badge&logo=githubsponsors&logoColor=white" alt="Sponsor on GitHub" height="32"></a>&nbsp;
<a href="https://github.com/sponsors/jojin1709"><img src="https://img.shields.io/badge/Become_a_Sponsor-EA4AAA?style=for-the-badge&logo=githubsponsors&logoColor=white" alt="Become a Sponsor"></a>

<br/>

<a href="https://github.com/jojin1709/APKlens-/stargazers"><img src="https://img.shields.io/badge/Star-3DDC84?style=for-the-badge&logo=github&logoColor=black" alt="Star on GitHub"></a>&nbsp;
<a href="https://www.linkedin.com/in/jojin-john/"><img src="https://img.shields.io/badge/Connect_on_LinkedIn-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white" alt="LinkedIn"></a>

<br/><br/>

<a href="https://www.linkedin.com/in/jojin-john/">
  <img src="public/jojin.png" width="72" height="72" style="border-radius: 50%;" alt="Jojin John" />
</a>

<br/>

**Developed by [JOJIN JOHN](https://www.linkedin.com/in/jojin-john/)** . [GitHub](https://github.com/jojin1709) . [LinkedIn](https://www.linkedin.com/in/jojin-john/) . [Sponsor](https://github.com/sponsors/jojin1709)

</div>
