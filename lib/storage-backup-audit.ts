/**
 * Pure TypeScript Android Storage & Backup Security Auditor.
 * Evaluates android:allowBackup, fullBackupContent, dataExtractionRules,
 * and dangerous storage permissions or SharedPreferences flags.
 */

export interface StorageFinding {
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  recommendation: string;
}

export interface StorageAuditResult {
  allowBackup: boolean | null;
  fullBackupContent: string | null;
  dataExtractionRules: string | null;
  usesExternalStorage: boolean;
  managesAllFiles: boolean;
  insecureModeFlagsFound: string[];
  findings: StorageFinding[];
}

export function auditStorageAndBackup(
  manifestXml: string | null,
  permissions: string[],
  strings: string[]
): StorageAuditResult {
  let allowBackup: boolean | null = null;
  let fullBackupContent: string | null = null;
  let dataExtractionRules: string | null = null;
  const findings: StorageFinding[] = [];

  if (manifestXml) {
    try {
      const doc = new DOMParser().parseFromString(manifestXml, "application/xml");
      const app = doc.querySelector("application");
      if (app) {
        const ab = app.getAttribute("android:allowBackup") ?? app.getAttribute("allowBackup");
        if (ab !== null) {
          allowBackup = ab.toLowerCase() === "true";
        } else {
          // Default in Android is true unless targetSdk >= 31 or explicitly false
          allowBackup = true;
        }

        fullBackupContent =
          app.getAttribute("android:fullBackupContent") ?? app.getAttribute("fullBackupContent");
        dataExtractionRules =
          app.getAttribute("android:dataExtractionRules") ?? app.getAttribute("dataExtractionRules");
      }
    } catch {
      // Ignore XML parse errors
    }
  }

  // Backup vulnerability assessment
  if (allowBackup === true) {
    if (!fullBackupContent && !dataExtractionRules) {
      findings.push({
        severity: "high",
        title: "Unrestricted Application Data Backup Enabled",
        description:
          "android:allowBackup is set to true (or default) without custom backup rules. Anyone with physical access and USB debugging enabled can clone complete app private data, SharedPreferences, and SQLite databases via 'adb backup'.",
        recommendation:
          "Set android:allowBackup='false' in AndroidManifest.xml, or configure strict dataExtractionRules to exclude authentication tokens, session cookies, and private databases.",
      });
    } else {
      findings.push({
        severity: "medium",
        title: "Custom Backup Rules Configured",
        description: `Application allows backup with custom filtering: ${fullBackupContent || dataExtractionRules}. Verify that sensitive encryption keys and session databases are excluded.`,
        recommendation: "Review the referenced XML resource to ensure credentials and secret stores are blacklisted.",
      });
    }
  } else if (allowBackup === false) {
    findings.push({
      severity: "info",
      title: "Application Backup Disabled",
      description: "android:allowBackup='false' prevents unauthorized data extraction via adb backup.",
      recommendation: "Maintained safely according to OWASP MSTG-STORAGE-1.",
    });
  }

  // Storage permission analysis
  const usesExternalStorage = permissions.some(
    (p) =>
      p.includes("READ_EXTERNAL_STORAGE") ||
      p.includes("WRITE_EXTERNAL_STORAGE")
  );
  const managesAllFiles = permissions.some((p) => p.includes("MANAGE_EXTERNAL_STORAGE"));

  if (managesAllFiles) {
    findings.push({
      severity: "high",
      title: "Broad All-Files Storage Access (MANAGE_EXTERNAL_STORAGE)",
      description:
        "The application requests MANAGE_EXTERNAL_STORAGE, granting full read/write access to all files on the device outside the app sandbox.",
      recommendation: "Limit file access to Scoped Storage and MediaStore APIs whenever possible.",
    });
  } else if (usesExternalStorage) {
    findings.push({
      severity: "medium",
      title: "Shared External Storage Permission Requested",
      description:
        "The application requests legacy external storage permissions. Files written to shared external storage (/sdcard) can be read and tampered with by any other installed application.",
      recommendation: "Store private app data strictly in internal storage (getFilesDir() / getCacheDir()).",
    });
  }

  // Insecure SharedPreferences flags check
  const insecureModeFlagsFound: string[] = [];
  const stringPool = strings.join(" ");

  if (stringPool.includes("MODE_WORLD_READABLE")) {
    insecureModeFlagsFound.push("MODE_WORLD_READABLE");
    findings.push({
      severity: "critical",
      title: "Insecure File Creation Mode (MODE_WORLD_READABLE)",
      description:
        "References to MODE_WORLD_READABLE detected in bytecode strings. Files or preferences created with this flag are readable by any application on the device.",
      recommendation: "Replace with Context.MODE_PRIVATE or EncryptedSharedPreferences from AndroidX Security.",
    });
  }

  if (stringPool.includes("MODE_WORLD_WRITEABLE")) {
    insecureModeFlagsFound.push("MODE_WORLD_WRITEABLE");
    findings.push({
      severity: "critical",
      title: "Insecure File Creation Mode (MODE_WORLD_WRITEABLE)",
      description:
        "References to MODE_WORLD_WRITEABLE detected in bytecode strings. Files or preferences created with this flag can be modified or corrupted by malicious third-party apps.",
      recommendation: "Use Context.MODE_PRIVATE and validate data integrity using cryptographic MACs.",
    });
  }

  return {
    allowBackup,
    fullBackupContent,
    dataExtractionRules,
    usesExternalStorage,
    managesAllFiles,
    insecureModeFlagsFound,
    findings,
  };
}
