import type { APKCertificate } from "@/lib/apk-signer";

export type { APKCertificate };

export type APKFile = {
  path: string;
  size: number;
  type: "file" | "directory";
};

export type APKAnalysis = {
  id: string;
  fileName: string;
  size: number;
  sha256: string;
  analyzedAt: string;
  packageName: string | null;
  versionName: string | null;
  versionCode: string | null;
  minSdk: string | null;
  targetSdk: string | null;
  permissions: string[];
  activities: { name: string; exported: string | null }[];
  services: { name: string; exported: string | null }[];
  receivers: { name: string; exported: string | null }[];
  providers: { name: string; exported: string | null }[];
  urls: string[];
  domains: string[];
  webViews: string[];
  technologies: string[];
  dexFiles: { path: string; size: number; strings: number; classCount?: number; methodCount?: number; classes?: string[] }[];
  nativeLibraries: { path: string; size: number }[];
  resources: string[];
  assets: string[];
  manifestXml: string | null;
  certificate: APKCertificate | null;
  files: APKFile[];
  findings: {
    severity: "high" | "medium" | "low" | "info";
    title: string;
    evidence: string;
  }[];
};