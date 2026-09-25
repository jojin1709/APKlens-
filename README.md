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

![](https://img.shields.io/badge/15_Analysis_Modules-3DDC84?style=for-the-badge&labelColor=0D1117)
&nbsp;![](https://img.shields.io/badge/100%25_Client_Side-3DDC84?style=for-the-badge&labelColor=0D1117&logo=googlechrome&logoColor=white)
&nbsp;![](https://img.shields.io/badge/Binary_AXML_Decoder-3DDC84?style=for-the-badge&labelColor=0D1117&logo=android&logoColor=white)
&nbsp;![](https://img.shields.io/badge/JADX_AST_Decompiler-3DDC84?style=for-the-badge&labelColor=0D1117)
&nbsp;![](https://img.shields.io/badge/SARIF_2.1.0_%2B_PDF-3DDC84?style=for-the-badge&labelColor=0D1117&logo=adobeacrobatreader&logoColor=white)
&nbsp;![](https://img.shields.io/badge/Zero_Cloud_Uploads-3DDC84?style=for-the-badge&labelColor=0D1117)

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
- **Native Binary AXML Decoder** — decodes compiled binary AndroidManifest.xml files directly in TypeScript with sub-second performance.
- **Automated SAST & Secret Hunter** — sweeps bytecode strings for exposed AWS tokens, Google Cloud API keys, Firebase URLs, Stripe keys, and insecure crypto ciphers.
- **On-Demand JADX AST Decompiler** — reconstructs clean Java and Kotlin source code on-demand for specific classes with real-time progress indicators.
- **Native ELF (.so) Library Auditor** — inspects native shared objects (ARMv7, ARM64, x86, x86_64), mapping dynamic symbol tables and exported JNI functions.
- **Compliance-Ready Reporting** — export OASIS SARIF 2.1.0 reports for GitHub Code Scanning / GitLab DevSecOps pipelines, plus printable PDF reports with a security score.
- **Encrypted IndexedDB Session Vault** — persists previous scan reports locally in your browser IndexedDB for historical comparison without re-uploading.

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
| 7 | **DEX & Decompiler** | Dalvik class catalog, method metrics, string pools, and on-demand JADX source decompilation |
| 8 | **Native Libraries (.so)** | ELF32/ELF64 architecture inspection, endianness, linked shared objects, and exported JNI entry points |
| 9 | **Resources** | Visual catalog of application layouts, values, drawables, and compiled resource references |
| 10 | **Network & URLs** | Extracted HTTP/HTTPS endpoints, domain names, WebViews, and network security configuration checks |
| 11 | **Security & Secrets** | Hardcoded credential scanner (AWS, Google, Firebase, Stripe) and insecure cryptography checks |
| 12 | **OWASP Mobile Top 10** | Automated mapping of findings to OWASP MASTG / Mobile Top 10 risk categories |
| 13 | **Certificate & Signing** | Extraction of v1/v2/v3 X.509 certs, validity dates, and SHA-256 fingerprints |
| 14 | **Technology Stack** | Fingerprinting of frameworks and SDKs (Jetpack, Flutter, React Native, Unity, OkHttp, Firebase) |
| 15 | **Reports & Exports** | One-click JSON dumps, OASIS SARIF 2.1.0 exports, and printable executive PDF reports |

---

## Key Capabilities

- **Pure TypeScript AXML Engine:** Binary XML chunk parsing without requiring Android SDK tools (aapt, apkanalyzer, or apktool).
- **X.509 Certificate Extractor:** Parses ASN.1 DER blocks from META-INF/*.RSA and APK Signing Block structures.
- **Multi-DEX Bytecode Sweeper:** Recursively parses classes.dex, classes2.dex, ... identifying class descriptors, method counts, and printable string tables.
- **Entropy & Regex Secret Engine:** Shannon entropy and targeted regex signatures to detect accidentally committed tokens and API keys.
- **Premium Atomic Black UI:** Sleek dark Atomic Black aesthetic (#08080a), Android green (#3DDC84) accents, fixed sidebar navigator, and a premium APK scan loading experience.

---

## Architecture & How It Works

`mermaid
flowchart TD
    A["User selects .apk file"] --> B["Browser File API / ArrayBuffer Sandbox"]
    B --> C["Web Crypto API: SHA-256 Fingerprint"]
    B --> D["JSZip In-Memory Stream Decompression"]
    D --> E["Extract File Manifest & Sizes"]
    D --> F["Dalvik DEX Class & Method Inspector"]
    D --> G["Binary AXML Chunk Parser"]
    B --> H["X.509 ASN.1 Certificate Parser"]
    F --> I["Printable Strings & Endpoint Extraction"]
    F --> J["Framework & Library Signatures"]
    G --> K["Permissions & Component Export Audit"]
    G --> L["Security Indicators & Misconfigurations"]
    C --> M["APKLens Reactive State Engine"]
    E --> M
    H --> M
    I --> M
    J --> M
    K --> M
    L --> M
    M --> N["Interactive Web UI: apklens-in.vercel.app"]
    M --> O["IndexedDB Local Session Vault"]
    M --> P["Export SARIF 2.1.0 & PDF Report"]
`

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
