import type { APKCertificate } from "@/lib/apk-signer";
import type { NativeLibraryInfo } from "@/lib/elf-parser";
import type { SecretFinding } from "@/lib/secret-scanner";
import type { NetworkSecurityConfigResult } from "@/lib/network-security-config-parser";
import type { MatchedTracker } from "@/lib/tracker-detector";
import type { StorageAuditResult } from "@/lib/storage-backup-audit";

export type {
  APKCertificate,
  NativeLibraryInfo,
  SecretFinding,
  NetworkSecurityConfigResult,
  MatchedTracker,
  StorageAuditResult,
};

export type APKFile = {
  path: string;
  size: number;
  type: "file" | "directory";
};

export type DeepLinkInfo = {
  scheme: string;
  host: string | null;
  path: string | null;
  activity: string;
  isBrowsable: boolean;
  uri: string;
  adbCommand: string;
};

export type APKAnalysis = {
  id: string;
  fileName: string;
  size: number;
  sha256: string;
  analyzedAt: string;
  packageName: string | null;
  icon: string | null;
  versionName: string | null;
  versionCode: string | null;
  minSdk: string | null;
  targetSdk: string | null;
  permissions: string[];
  activities: { name: string; exported: string | null }[];
  services: { name: string; exported: string | null }[];
  receivers: { name: string; exported: string | null }[];
  providers: { name: string; exported: string | null }[];
  deepLinks: DeepLinkInfo[];
  urls: string[];
  domains: string[];
  webViews: string[];
  strings: string[];
  technologies: string[];
  dexFiles: {
    path: string;
    size: number;
    strings: number;
    classCount?: number;
    methodCount?: number;
    classes?: string[];
  }[];
  nativeLibraries: NativeLibraryInfo[];
  secrets: SecretFinding[];
  networkSecurityConfig?: NetworkSecurityConfigResult | null;
  trackers?: MatchedTracker[];
  storageAudit?: StorageAuditResult | null;
  resources: string[];
  assets: string[];
  manifestXml: string | null;
  certificate: APKCertificate | null;
  files: APKFile[];
  findings: {
    severity: "critical" | "high" | "medium" | "low" | "info";
    title: string;
    evidence: string;
  }[];
};