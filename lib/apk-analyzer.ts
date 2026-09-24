import JSZip from "jszip";
import type { APKAnalysis, APKFile } from "@/types/apk";

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
  return [...new Set(matches)].slice(0, 20000);
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

function parseManifest(xml: string) {
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

export async function analyzeAPK(file: File): Promise<APKAnalysis> {
  const buffer = await file.arrayBuffer();
  const hash = await sha256(buffer);
  const zip = await JSZip.loadAsync(buffer);

  const files: APKFile[] = [];
  const resources: string[] = [];
  const assets: string[] = [];
  const nativeLibraries: { path: string; size: number }[] = [];
  const dexFiles: { path: string; size: number; strings: number }[] = [];
  let manifestXml: string | null = null;
  const urls: string[] = [];
  const webViews: string[] = [];
  const technologies = new Set<string>();

  const names = Object.keys(zip.files).filter((n) => !zip.files[n].dir);
  for (const path of names) {
    const entry = zip.files[path];
    const bytes = await entry.async("uint8array");
    files.push({ path, size: bytes.byteLength, type: "file" });

    if (path === "AndroidManifest.xml") {
      // Android binary XML is common in APKs. Plain XML is supported directly;
      // binary AXML is intentionally reported as unavailable rather than fabricated.
      const text = decodeBytes(bytes).trim();
      if (text.startsWith("<")) manifestXml = text;
    }
    if (path.startsWith("res/")) resources.push(path);
    if (path.startsWith("assets/")) assets.push(path);
    if (path.startsWith("lib/") && path.endsWith(".so")) nativeLibraries.push({ path, size: bytes.byteLength });
    if (/^classes\d*\.dex$/.test(path)) {
      const strings = extractStrings(bytes);
      dexFiles.push({ path, size: bytes.byteLength, strings: strings.length });
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

  if (names.some(n => n.startsWith("kotlin/"))) technologies.add("Kotlin");
  if (names.some(n => n.startsWith("androidx/"))) technologies.add("AndroidX");
  if (names.some(n => n.startsWith("META-INF/"))) technologies.add("Android APK");
  if (nativeLibraries.length) technologies.add("Native code");

  const domains = unique(urls.map(u => {
    try { return new URL(u).hostname; } catch { return ""; }
  }).filter(Boolean));

  const manifest = manifestXml ? parseManifest(manifestXml) : {
    packageName: null, versionName: null, versionCode: null, minSdk: null, targetSdk: null,
    permissions: [], activities: [], services: [], receivers: [], providers: [],
    debuggable: null, allowBackup: null, usesCleartextTraffic: null
  };

  const findings: APKAnalysis["findings"] = [];
  if (!manifestXml) {
    findings.push({
      severity: "info",
      title: "Manifest requires binary AXML decoding",
      evidence: "The APK contains AndroidManifest.xml, but it is binary Android XML. Browser-only mode does not claim to decode it."
    });
  }
  if (manifest.debuggable === "true") findings.push({
    severity: "high",
    title: "Application is marked debuggable",
    evidence: "AndroidManifest.xml: android:debuggable=\"true\""
  });
  if (manifest.allowBackup === "true") findings.push({
    severity: "medium",
    title: "Backup is enabled",
    evidence: "AndroidManifest.xml: android:allowBackup=\"true\""
  });
  if (manifest.usesCleartextTraffic === "true") findings.push({
    severity: "medium",
    title: "Cleartext traffic is explicitly allowed",
    evidence: "AndroidManifest.xml: android:usesCleartextTraffic=\"true\""
  });
  if (manifest.permissions.some(p => /READ_EXTERNAL_STORAGE|WRITE_EXTERNAL_STORAGE|CAMERA|RECORD_AUDIO|ACCESS_FINE_LOCATION/i.test(p))) {
    findings.push({
      severity: "info",
      title: "Sensitive permissions requested",
      evidence: manifest.permissions.filter(p => /READ_EXTERNAL_STORAGE|WRITE_EXTERNAL_STORAGE|CAMERA|RECORD_AUDIO|ACCESS_FINE_LOCATION/i.test(p)).join(", ")
    });
  }

  return {
    id: crypto.randomUUID(),
    fileName: file.name,
    size: file.size,
    sha256: hash,
    analyzedAt: new Date().toISOString(),
    packageName: manifest.packageName,
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
    resources,
    assets,
    manifestXml,
    files,
    findings
  };
}