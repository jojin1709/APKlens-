#!/usr/bin/env node

/**
 * APKLens Headless CI/CD Static Auditor
 * Analyzes an APK file and outputs findings to console and SARIF v2.1.0 format
 * for GitHub Advanced Security code scanning.
 * 
 * Usage:
 *   node scripts/apklens-ci.mjs <path-to-apk> [--sarif <output-file>] [--fail-on-high]
 */

import fs from "fs";
import path from "path";
import JSZip from "jszip";

const args = process.argv.slice(2);
if (args.length === 0 || args[0] === "--help" || args[0] === "-h") {
  console.log(`
APKLens Headless CI/CD Static Security Auditor
Usage:
  node scripts/apklens-ci.mjs <path-to-apk> [options]

Options:
  --sarif <file>     Write findings to a SARIF v2.1.0 file (e.g. apklens.sarif)
  --fail-on-high     Exit with code 1 if any CRITICAL or HIGH vulnerabilities are detected
  --json             Print JSON results to stdout
  --help, -h         Show this help message
`);
  process.exit(0);
}

const apkPath = args[0];
let sarifOutPath = null;
let failOnHigh = false;
let jsonOut = false;

for (let i = 1; i < args.length; i++) {
  if (args[i] === "--sarif" && args[i + 1]) {
    sarifOutPath = args[i + 1];
    i++;
  } else if (args[i] === "--fail-on-high") {
    failOnHigh = true;
  } else if (args[i] === "--json") {
    jsonOut = true;
  }
}

if (!fs.existsSync(apkPath)) {
  console.error(`[-] Error: APK file not found at path: ${apkPath}`);
  process.exit(1);
}

console.log(`[*] APKLens CI Auditor starting analysis on: ${path.basename(apkPath)}`);

async function runAudit() {
  const buffer = fs.readFileSync(apkPath);
  const zip = await JSZip.loadAsync(buffer);

  const findings = [];
  let manifestText = "";
  let packageName = "unknown.package";
  let allowBackup = true;
  let debuggable = false;

  // 1. Check AndroidManifest.xml
  const manifestFile = zip.file("AndroidManifest.xml");
  if (manifestFile) {
    const rawBytes = await manifestFile.async("uint8array");
    // Simple string extraction from binary AXML
    const strMatch = new TextDecoder("latin1").decode(rawBytes);
    manifestText = strMatch;

    if (strMatch.includes("android:debuggable") && (strMatch.includes("\x01\x00\x00\x00") || strMatch.includes('"true"'))) {
      debuggable = true;
      findings.push({
        id: "APK-001",
        ruleId: "manifest-debuggable",
        level: "error",
        title: "Application is Debuggable (android:debuggable=true)",
        description: "Enables JDWP process attachment and unauthorized memory/data dumping.",
        file: "AndroidManifest.xml"
      });
    }

    if (strMatch.includes("android:allowBackup") && strMatch.includes("\x00\x00\x00\x00")) {
      allowBackup = false;
    } else {
      findings.push({
        id: "APK-002",
        ruleId: "manifest-allowbackup",
        level: "warning",
        title: "Application Backup Enabled (android:allowBackup=true)",
        description: "App private sandbox data can be backed up and dumped via adb backup.",
        file: "AndroidManifest.xml"
      });
    }

    if (strMatch.includes("usesCleartextTraffic")) {
      findings.push({
        id: "APK-003",
        ruleId: "manifest-cleartext-traffic",
        level: "warning",
        title: "Cleartext HTTP Traffic Permitted",
        description: "Application allows insecure unencrypted HTTP network communication.",
        file: "AndroidManifest.xml"
      });
    }
  }

  // 2. Scan DEX files for secrets and weak crypto
  const dexFiles = Object.keys(zip.files).filter((f) => f.endsWith(".dex"));
  for (const dexName of dexFiles) {
    const dexBytes = await zip.files[dexName].async("uint8array");
    const dexStr = new TextDecoder("latin1").decode(dexBytes);

    if (dexStr.includes("DES/ECB") || dexStr.includes("AES/ECB")) {
      findings.push({
        id: "APK-004",
        ruleId: "crypto-weak-cipher-mode",
        level: "error",
        title: "Insecure ECB Cipher Mode Detected",
        description: "Electronic Codebook (ECB) mode does not use an IV and is cryptographically weak.",
        file: dexName
      });
    }

    if (dexStr.includes("TrustAllCerts") || dexStr.includes("ALLOW_ALL_HOSTNAME_VERIFIER")) {
      findings.push({
        id: "APK-005",
        ruleId: "ssl-trust-all-certs",
        level: "error",
        title: "TrustAllCerts / Permissive HostnameVerifier Bypass",
        description: "Hardcoded SSL trust-all bypass invalidates TLS certificate validation.",
        file: dexName
      });
    }

    // Generic secret regex scan
    const secretRegex = /(?:AKIA[0-9A-Z]{16})|(?:ghp_[0-9a-zA-Z]{36})|(?:AIza[0-9A-Za-z\\-_]{35})/g;
    let match;
    while ((match = secretRegex.exec(dexStr)) !== null) {
      findings.push({
        id: "APK-006",
        ruleId: "hardcoded-api-key",
        level: "error",
        title: `Hardcoded API Secret Detected (${match[0].slice(0, 8)}...)`,
        description: "High-entropy cloud credential embedded in compiled DEX bytecode.",
        file: dexName
      });
    }
  }

  console.log(`\n================ APKLens Static Audit Summary ================`);
  console.log(`Scanned File: ${path.basename(apkPath)}`);
  console.log(`Findings: ${findings.length}`);
  findings.forEach((f) => {
    const icon = f.level === "error" ? "❌ CRITICAL/HIGH" : "⚠️  MEDIUM/WARNING";
    console.log(`  ${icon} [${f.ruleId}] ${f.title} (${f.file})`);
  });
  console.log(`===============================================================\n`);

  if (sarifOutPath) {
    const sarif = {
      $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "APKLens",
              version: "1.0.0",
              informationUri: "https://github.com/jojin1709/APKlens-",
              rules: findings.map((f) => ({
                id: f.ruleId,
                shortDescription: { text: f.title },
                fullDescription: { text: f.description },
                defaultConfiguration: { level: f.level }
              }))
            }
          },
          results: findings.map((f) => ({
            ruleId: f.ruleId,
            level: f.level,
            message: { text: `${f.title}: ${f.description}` },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: f.file },
                  region: { startLine: 1 }
                }
              }
            ]
          }))
        }
      ]
    };

    fs.writeFileSync(sarifOutPath, JSON.stringify(sarif, null, 2), "utf-8");
    console.log(`[+] Successfully generated SARIF report at: ${sarifOutPath}`);
  }

  const hasHighOrCritical = findings.some((f) => f.level === "error");
  if (failOnHigh && hasHighOrCritical) {
    console.error(`[-] Build failed: One or more HIGH/CRITICAL security vulnerabilities found.`);
    process.exit(1);
  }

  console.log(`[+] APKLens Static Audit completed successfully.`);
}

runAudit().catch((err) => {
  console.error("[-] Audit encountered error:", err);
  process.exit(1);
});
