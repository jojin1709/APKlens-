import type { APKAnalysis } from "@/types/apk";

export interface OWASPCategory {
  id: string; // e.g., "M1"
  name: string;
  title: string;
  status: "pass" | "warn" | "fail";
  score: number;
  description: string;
  findings: string[];
  remediation: string;
}

/**
 * Maps static analysis results to the official OWASP Mobile Top 10 (2024 Release).
 */
export function mapToOWASPTop10(analysis: APKAnalysis): OWASPCategory[] {
  const secrets = analysis.secrets || [];
  const findings = analysis.findings || [];
  const manifest = {
    debuggable: analysis.findings.some(f => f.title.includes("debuggable")),
    allowBackup: analysis.findings.some(f => f.title.includes("Backup")),
    cleartext: analysis.findings.some(f => f.title.includes("Cleartext")),
  };

  // M1: Improper Credential Usage
  const credSecrets = secrets.filter(s =>
    ["aws-key", "google-api-key", "stripe-key", "openai-api-key", "github-token", "database-uri", "sendgrid-key", "twilio-credentials", "bearer-token", "private-key"].includes(s.type)
  );
  const m1Status: "pass" | "warn" | "fail" = credSecrets.some(s => s.severity === "critical")
    ? "fail"
    : credSecrets.length > 0
    ? "warn"
    : "pass";

  // M2: Inadequate Supply Chain Security
  const expiredCert = findings.some(f => f.title.includes("expired") || f.title.includes("Unsigned"));
  const m2Status: "pass" | "warn" | "fail" = expiredCert ? "fail" : "pass";

  // M3: Insecure Authentication / Authorization
  const exportedWithoutPerm = analysis.activities.filter(a => a.exported === "true").length > 3;
  const m3Status: "pass" | "warn" | "fail" = exportedWithoutPerm ? "warn" : "pass";

  // M4: Insufficient Input / Output Validation
  const hasBrowsableDeepLinks = (analysis.deepLinks || []).some(dl => dl.isBrowsable);
  const m4Status: "pass" | "warn" | "fail" = hasBrowsableDeepLinks ? "warn" : "pass";

  // M5: Insecure Communication
  const m5Status: "pass" | "warn" | "fail" = manifest.cleartext ? "fail" : "pass";

  // M6: Inadequate Privacy Controls
  const sensitivePerms = analysis.permissions.filter(p =>
    /READ_EXTERNAL_STORAGE|WRITE_EXTERNAL_STORAGE|CAMERA|RECORD_AUDIO|ACCESS_FINE_LOCATION|READ_CONTACTS|READ_SMS/i.test(p)
  );
  const m6Status: "pass" | "warn" | "fail" = sensitivePerms.length > 3 ? "warn" : sensitivePerms.length > 0 ? "warn" : "pass";

  // M7: Insufficient Binary Protections
  const m7Status: "pass" | "warn" | "fail" = manifest.debuggable ? "fail" : "pass";

  // M8: Security Misconfiguration
  const exportedComponents = (analysis.receivers.filter(r => r.exported === "true").length + analysis.providers.filter(p => p.exported === "true").length);
  const m8Status: "pass" | "warn" | "fail" = exportedComponents > 0 ? "warn" : "pass";

  // M9: Insecure Data Storage
  const m9Status: "pass" | "warn" | "fail" = manifest.allowBackup ? "warn" : "pass";

  // M10: Insufficient Cryptography
  const cryptoFlaws = secrets.filter(s => ["insecure-ecb", "weak-des", "weak-md5"].includes(s.type));
  const m10Status: "pass" | "warn" | "fail" = cryptoFlaws.some(c => c.severity === "high") ? "fail" : cryptoFlaws.length ? "warn" : "pass";

  return [
    {
      id: "M1",
      name: "Improper Credential Usage",
      title: "Hardcoded Secrets & API Tokens",
      status: m1Status,
      score: m1Status === "pass" ? 100 : m1Status === "warn" ? 50 : 0,
      description: "Hardcoded API keys, private keys, database credentials, or bearer tokens embedded in compiled bytecode.",
      findings: credSecrets.map(s => `${s.name} (${s.severity.toUpperCase()})`),
      remediation: "Migrate all sensitive secrets and signing tokens to Android Keystore or fetch dynamically from backend with short-lived OAuth tokens.",
    },
    {
      id: "M2",
      name: "Inadequate Supply Chain Security",
      title: "Signature & Certificate Integrity",
      status: m2Status,
      score: m2Status === "pass" ? 100 : 0,
      description: "Audit for unsigned packages, expired X.509 certificates, and vulnerable native library dependencies.",
      findings: expiredCert ? ["APK signature expired or untrusted certificate scheme."] : ["Cryptographic signing certificate valid."],
      remediation: "Sign releases using APK Signature Scheme v2/v3 with 2048-bit RSA or 256-bit ECDSA keys and renew expired certificates.",
    },
    {
      id: "M3",
      name: "Insecure Authentication / Authorization",
      title: "Component Export Access Control",
      status: m3Status,
      score: m3Status === "pass" ? 100 : 60,
      description: "Publicly accessible activities, aliases, and interfaces that can be invoked by third-party malicious apps.",
      findings: [`${analysis.activities.filter(a => a.exported === "true").length} activities marked android:exported="true".`],
      remediation: "Set android:exported=\"false\" on internal components or enforce custom signature-level permissions (android:permission).",
    },
    {
      id: "M4",
      name: "Insufficient Input / Output Validation",
      title: "Deep Link & Intent Validation",
      status: m4Status,
      score: m4Status === "pass" ? 100 : 65,
      description: "Browsable custom URL schemes and intent filters vulnerable to intent spoofing or CSRF.",
      findings: (analysis.deepLinks || []).map(dl => `Browsable scheme: ${dl.uri}`),
      remediation: "Implement strict parameter validation and verify Android App Links (Digital Asset Links) with autoVerify=\"true\".",
    },
    {
      id: "M5",
      name: "Insecure Communication",
      title: "Cleartext Traffic & TLS Security",
      status: m5Status,
      score: m5Status === "pass" ? 100 : 20,
      description: "Unencrypted HTTP transmissions and lack of network security configuration enforcement.",
      findings: manifest.cleartext ? ["android:usesCleartextTraffic=\"true\" enabled in manifest."] : ["Cleartext traffic disabled by default."],
      remediation: "Set android:usesCleartextTraffic=\"false\" and enforce TLS 1.3 with Certificate Pinning in network_security_config.xml.",
    },
    {
      id: "M6",
      name: "Inadequate Privacy Controls",
      title: "Sensitive Hardware & User Data Permissions",
      status: m6Status,
      score: m6Status === "pass" ? 100 : 70,
      description: "Over-privileged applications requesting invasive hardware sensors, background location, or SMS/call data.",
      findings: sensitivePerms.map(p => p.split(".").pop() || p),
      remediation: "Adhere to the Principle of Least Privilege. Only request runtime permissions when actively needed.",
    },
    {
      id: "M7",
      name: "Insufficient Binary Protections",
      title: "Runtime Debugging & Anti-Analysis",
      status: m7Status,
      score: m7Status === "pass" ? 100 : 10,
      description: "Debuggable binaries that permit live memory inspection, breakpoints, and ADB method hooks.",
      findings: manifest.debuggable ? ["android:debuggable=\"true\" explicitly declared!"] : ["Binary is not marked debuggable."],
      remediation: "Ensure android:debuggable=\"false\" in release builds and enable R8 / ProGuard code shrinking and obfuscation.",
    },
    {
      id: "M8",
      name: "Security Misconfiguration",
      title: "Exposed Receivers & Content Providers",
      status: m8Status,
      score: m8Status === "pass" ? 100 : 50,
      description: "Exported broadcast receivers and content providers that can leak private app databases or trigger malicious actions.",
      findings: [`${exportedComponents} exported receivers/providers detected without explicit permission guards.`],
      remediation: "Audit all content providers and broadcast receivers. Restrict exported providers with android:grantUriPermissions=\"false\".",
    },
    {
      id: "M9",
      name: "Insecure Data Storage",
      title: "Local Backup & Storage Extraction",
      status: m9Status,
      score: m9Status === "pass" ? 100 : 60,
      description: "Application data extraction via ADB backup command or world-readable internal storage.",
      findings: manifest.allowBackup ? ["android:allowBackup=\"true\" permits ADB backup extraction."] : ["ADB backup disabled."],
      remediation: "Set android:allowBackup=\"false\" unless an explicit BackupAgent with encrypted cloud storage is implemented.",
    },
    {
      id: "M10",
      name: "Insufficient Cryptography",
      title: "Weak Ciphers & Broken Hashing",
      status: m10Status,
      score: m10Status === "pass" ? 100 : m10Status === "warn" ? 50 : 25,
      description: "Deprecated cryptographic ciphers (DES, 3DES, AES/ECB) and collision-vulnerable hash functions (MD5, SHA-1).",
      findings: cryptoFlaws.map(c => `${c.name} detected in Dalvik bytecode.`),
      remediation: "Standardize on AES-256-GCM authenticated encryption and SHA-256 / SHA-512 hashing.",
    },
  ];
}
