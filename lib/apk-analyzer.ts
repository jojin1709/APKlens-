import JSZip from "jszip";
import type { APKAnalysis, APKFile } from "@/types/apk";
import { decodeAxml, isBinaryAxml, type DecodedManifest } from "@/lib/axml-parser";
import { parseV1Signature, parseV2V3Signature, type APKCertificate } from "@/lib/apk-signer";
import { parseDex } from "@/lib/dex-parser";
import { scanForSecrets, type SecretFinding } from "@/lib/secret-scanner";
import { parseElf, type NativeLibraryInfo } from "@/lib/elf-parser";

// Cache for extracted DEX file blobs to enable ultra-fast single-class decompilation
export const dexBlobCache = new Map<string, Blob>();

function sha256(buffer: ArrayBuffer): Promise<string> {
  return crypto.subtle.digest("SHA-256", buffer).then((hash) =>
    [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("")
  );
}

function decodeBytes(bytes: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}

function extractStrings(bytes: Uint8Array): string[] {
  const text = decodeBytes(bytes);
  const matches = text.match(/[ -~]{4,}/g) || [];
  return [...new Set(matches)].slice(0, 25000);
}

function unique<T>(items: T[]): T[] {
  return [...new Set(items)];
}

function attr(el: Element, name: string): string | null {
  return el.getAttribute(`android:${name}`) ?? el.getAttribute(name);
}

function normalizeComponentName(name: string | null, pkg: string | null): string {
  if (!name) return "";
  if (name.startsWith(".")) return `${pkg ?? ""}${name}`;
  if (!name.includes(".") && pkg) return `${pkg}.${name}`;
  return name;
}

function parseManifest(xml: string): DecodedManifest {
  const doc = new DOMParser().parseFromString(xml, "application/xml");
  const manifest = doc.querySelector("manifest");
  const app = doc.querySelector("application");
  const pkg = manifest?.getAttribute("package") ?? null;

  const permissions = unique(
    [...doc.querySelectorAll("uses-permission, uses-permission-sdk-23, uses-permission-sdk-m")].map(
      (x) => attr(x, "name")
    ).filter(Boolean) as string[]
  );

  const readComponents = (selector: string) =>
    [...doc.querySelectorAll(selector)].map((x) => ({
      name: normalizeComponentName(attr(x, "name"), pkg),
      exported: attr(x, "exported")
    })).filter(x => x.name);

  return {
    xml,
    packageName: pkg,
    versionName: manifest?.getAttribute("android:versionName") ?? manifest?.getAttribute("versionName") ?? null,
    versionCode: manifest?.getAttribute("android:versionCode") ?? manifest?.getAttribute("versionCode") ?? null,
    minSdk: doc.querySelector("uses-sdk")?.getAttribute("android:minSdkVersion") ?? null,
    targetSdk: doc.querySelector("uses-sdk")?.getAttribute("android:targetSdkVersion") ?? null,
    permissions,
    activities: readComponents("activity, activity-alias"),
    services: readComponents("service"),
    receivers: readComponents("receiver"),
    providers: readComponents("provider"),
    debuggable: app ? attr(app, "debuggable") : null,
    allowBackup: app ? attr(app, "allowBackup") : null,
    usesCleartextTraffic: app ? attr(app, "usesCleartextTraffic") : null
  };
}

async function extractAppIcon(zip: JSZip): Promise<string | null> {
  const iconPatterns = [
    /res\/mipmap-xxxhdpi[^\/]*\/.*(launcher|icon|app).*\.(png|webp)$/i,
    /res\/mipmap-xxhdpi[^\/]*\/.*(launcher|icon|app).*\.(png|webp)$/i,
    /res\/mipmap-xhdpi[^\/]*\/.*(launcher|icon|app).*\.(png|webp)$/i,
    /res\/mipmap-hdpi[^\/]*\/.*(launcher|icon|app).*\.(png|webp)$/i,
    /res\/drawable-xxxhdpi[^\/]*\/.*(launcher|icon|app).*\.(png|webp)$/i,
    /res\/drawable-xxhdpi[^\/]*\/.*(launcher|icon|app).*\.(png|webp)$/i,
    /res\/drawable-xhdpi[^\/]*\/.*(launcher|icon|app).*\.(png|webp)$/i,
    /res\/mipmap[^\/]*\/.*(launcher|icon|app).*\.(png|webp)$/i,
    /res\/drawable[^\/]*\/.*(launcher|icon|app).*\.(png|webp)$/i,
    /.*(ic_launcher|app_icon|ic_app).*\.(png|webp)$/i,
    /res\/.*icon.*\.(png|webp)$/i,
  ];

  const fileNames = Object.keys(zip.files).filter((n) => !zip.files[n].dir);

  for (const pattern of iconPatterns) {
    const match = fileNames.find((name) => pattern.test(name));
    if (match) {
      try {
        const file = zip.files[match];
        const base64 = await file.async("base64");
        const mime = match.toLowerCase().endsWith(".webp") ? "image/webp" : "image/png";
        return `data:${mime};base64,${base64}`;
      } catch (err) {
        console.warn("Failed reading icon candidate:", match, err);
      }
    }
  }

  return null;
}

export async function analyzeAPK(file: File): Promise<APKAnalysis> {
  const buffer = await file.arrayBuffer();
  const hash = await sha256(buffer);
  const zip = await JSZip.loadAsync(buffer);
  const icon = await extractAppIcon(zip);

  const files: APKFile[] = [];
  const resources: string[] = [];
  const assets: string[] = [];
  const nativeLibraries: NativeLibraryInfo[] = [];
  const dexFiles: APKAnalysis["dexFiles"] = [];
  let manifestXml: string | null = null;
  let decodedManifest: DecodedManifest | null = null;
  const urls: string[] = [];
  const webViews: string[] = [];
  const technologies = new Set<string>();
  const allCollectedStrings: string[] = [];

  const names = Object.keys(zip.files).filter((n) => !zip.files[n].dir);
  for (const path of names) {
    const entry = zip.files[path];
    const bytes = await entry.async("uint8array");
    files.push({ path, size: bytes.byteLength, type: "file" });

    if (path === "AndroidManifest.xml") {
      if (isBinaryAxml(bytes)) {
        try {
          decodedManifest = decodeAxml(bytes);
          manifestXml = decodedManifest.xml;
        } catch (err) {
          console.warn("Failed to decode binary AXML:", err);
        }
      } else {
        const text = decodeBytes(bytes).trim();
        if (text.startsWith("<")) {
          manifestXml = text;
          try {
            decodedManifest = parseManifest(text);
          } catch {
            // fallback
          }
        }
      }
    }
    
    if (path.startsWith("res/")) resources.push(path);
    if (path.startsWith("assets/")) assets.push(path);
    
    // Parse ELF native libraries (.so)
    if (path.startsWith("lib/") && path.endsWith(".so")) {
      const elfInfo = parseElf(bytes, path);
      nativeLibraries.push(elfInfo);
    }

    // Parse Dalvik Executable (DEX) bytecode
    if (/^classes\d*\.dex$/.test(path)) {
      const strings = extractStrings(bytes);
      allCollectedStrings.push(...strings);
      const dexData = parseDex(bytes, path);
      dexFiles.push({
        path,
        size: bytes.byteLength,
        strings: strings.length,
        classCount: dexData.classCount,
        methodCount: dexData.methodCount,
        classes: dexData.classes
      });

      // Cache DEX blob for fast on-demand decompilation without uploading entire APK
      try {
        const dexBlob = new Blob([bytes as unknown as BlobPart], { type: "application/octet-stream" });
        dexBlobCache.set(`${hash}:${path}`, dexBlob);
        dexBlobCache.set(`${hash}:primary`, dexBlob);
      } catch (e) {
        // Blob cache fallback
      }

      const joined = strings.join("\n");
      if (/kotlin\//i.test(joined) || /kotlin\.Metadata/i.test(joined)) technologies.add("Kotlin");
      if (/androidx\./i.test(joined)) technologies.add("AndroidX");
      if (/okhttp3/i.test(joined)) technologies.add("OkHttp");
      if (/retrofit2/i.test(joined)) technologies.add("Retrofit");
      if (/com\.google\.firebase/i.test(joined)) technologies.add("Firebase");
      if (/io\.flutter/i.test(joined)) technologies.add("Flutter");
      if (/com\.facebook\.react/i.test(joined)) technologies.add("React Native");
      if (/android\.webkit\.WebView/i.test(joined)) technologies.add("WebView");
      const foundUrls = joined.match(/https?:\/\/[^\s"'<>\\]+/g) || [];
      urls.push(...foundUrls.map(u => u.replace(/[),.;]+$/, "")));
      if (/android\.webkit\.WebView/i.test(joined)) webViews.push(path);
    }
  }

  // Parse APK Signature (v2/v3 from signing block, or v1 from META-INF)
  let certificate: APKCertificate | null = null;
  try {
    certificate = await parseV2V3Signature(buffer);
    if (!certificate) {
      const v1CertPath = names.find(n => /^META-INF\/.*\.(RSA|DSA|EC)$/i.test(n));
      if (v1CertPath) {
        const certEntry = zip.files[v1CertPath];
        const certBytes = await certEntry.async("uint8array");
        certificate = await parseV1Signature(certBytes);
      }
    }
  } catch (err) {
    console.warn("Failed to parse signature:", err);
  }

  // Automated SAST & Secret Scanner across collected bytecode strings and manifest
  if (manifestXml) {
    allCollectedStrings.push(...manifestXml.split(/\r?\n/));
  }
  const secrets: SecretFinding[] = scanForSecrets(allCollectedStrings);

  if (names.some(n => n.startsWith("kotlin/"))) technologies.add("Kotlin");
  if (names.some(n => n.startsWith("androidx/"))) technologies.add("AndroidX");
  if (names.some(n => n.startsWith("META-INF/"))) technologies.add("Android APK");
  if (nativeLibraries.length) technologies.add("Native code");

  const domains = unique(urls.map(u => {
    try { return new URL(u).hostname; } catch { return ""; }
  }).filter(Boolean));

  const manifest = decodedManifest ?? {
    xml: "",
    packageName: null, versionName: null, versionCode: null, minSdk: null, targetSdk: null,
    permissions: [], activities: [], services: [], receivers: [], providers: [],
    debuggable: null, allowBackup: null, usesCleartextTraffic: null
  };

  const findings: APKAnalysis["findings"] = [];
  if (!manifestXml) {
    findings.push({
      severity: "info",
      title: "No AndroidManifest.xml found",
      evidence: "The APK archive does not contain an AndroidManifest.xml entry."
    });
  }

  if (certificate) {
    findings.push({
      severity: "info",
      title: `APK is signed (${certificate.scheme})`,
      evidence: `Subject: ${certificate.subject} · Algorithm: ${certificate.sigAlg}`
    });
    try {
      const expiry = new Date(certificate.validTo);
      if (!isNaN(expiry.getTime()) && expiry < new Date()) {
        findings.push({
          severity: "high",
          title: "Signing certificate has expired",
          evidence: `Certificate expired on ${certificate.validTo}`
        });
      }
    } catch {
      // ignore date parse error
    }
  } else {
    findings.push({
      severity: "medium",
      title: "Unsigned APK / No valid signature detected",
      evidence: "No valid APK v1 (JAR) or v2/v3 (APK Signing Block) signature block was detected."
    });
  }

  if (manifest.debuggable === "true") findings.push({
    severity: "high",
    title: "Application is marked debuggable",
    evidence: "AndroidManifest.xml: android:debuggable=\"true\" (Allows attackers to attach runtime debuggers and dump memory)"
  });
  if (manifest.allowBackup === "true") findings.push({
    severity: "medium",
    title: "Backup is enabled",
    evidence: "AndroidManifest.xml: android:allowBackup=\"true\" (Application data can be extracted via ADB backup)"
  });
  if (manifest.usesCleartextTraffic === "true") findings.push({
    severity: "medium",
    title: "Cleartext HTTP traffic is explicitly allowed",
    evidence: "AndroidManifest.xml: android:usesCleartextTraffic=\"true\" (Traffic is vulnerable to MITM interception)"
  });
  if (manifest.permissions.some(p => /READ_EXTERNAL_STORAGE|WRITE_EXTERNAL_STORAGE|CAMERA|RECORD_AUDIO|ACCESS_FINE_LOCATION/i.test(p))) {
    findings.push({
      severity: "info",
      title: "Sensitive permissions requested",
      evidence: manifest.permissions.filter(p => /READ_EXTERNAL_STORAGE|WRITE_EXTERNAL_STORAGE|CAMERA|RECORD_AUDIO|ACCESS_FINE_LOCATION/i.test(p)).join(", ")
    });
  }

  // Append SAST Secret Findings
  for (const s of secrets) {
    findings.push({
      severity: s.severity === "critical" ? "critical" : s.severity,
      title: `Secret / Vulnerability: ${s.name}`,
      evidence: `${s.description} | Matched Pattern: ${s.match}`
    });
  }

  return {
    id: crypto.randomUUID(),
    fileName: file.name,
    size: file.size,
    sha256: hash,
    analyzedAt: new Date().toISOString(),
    packageName: manifest.packageName,
    icon,
    versionName: manifest.versionName,
    versionCode: manifest.versionCode,
    minSdk: manifest.minSdk,
    targetSdk: manifest.targetSdk,
    permissions: manifest.permissions,
    activities: manifest.activities,
    services: manifest.services,
    receivers: manifest.receivers,
    providers: manifest.providers,
    urls: unique(urls),
    domains,
    webViews: unique(webViews),
    technologies: [...technologies],
    dexFiles,
    nativeLibraries,
    secrets,
    resources,
    assets,
    manifestXml,
    certificate,
    files,
    findings
  };
}