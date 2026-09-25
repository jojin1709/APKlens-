/**
 * Pure TypeScript APK Version Comparison & Diff Engine.
 * Compares two APK analyses to identify security regressions, newly introduced permissions,
 * exported attack surfaces, tracker SDK additions, and binary size deltas.
 */

import type { APKAnalysis } from "@/types/apk";

export interface DiffItem<T> {
  added: T[];
  removed: T[];
  common: T[];
}

export interface APKDiffReport {
  baseApk: {
    fileName: string;
    versionName: string | null;
    versionCode: string | null;
    size: number;
    sha256: string;
  };
  targetApk: {
    fileName: string;
    versionName: string | null;
    versionCode: string | null;
    size: number;
    sha256: string;
  };
  sizeDeltaBytes: number;
  sizeDeltaPercent: number;
  permissions: DiffItem<string>;
  exportedActivities: DiffItem<string>;
  exportedServices: DiffItem<string>;
  exportedReceivers: DiffItem<string>;
  exportedProviders: DiffItem<string>;
  trackers: DiffItem<string>;
  newCriticalFindings: string[];
  resolvedFindings: string[];
  summary: {
    regressionsCount: number;
    improvementsCount: number;
    riskTrend: "increased" | "decreased" | "stable";
  };
}

export function compareAPKs(base: APKAnalysis, target: APKAnalysis): APKDiffReport {
  const diffList = <T>(baseArr: T[], targetArr: T[], keyFn: (item: T) => string = String): DiffItem<T> => {
    const baseMap = new Map<string, T>(baseArr.map((i) => [keyFn(i), i]));
    const targetMap = new Map<string, T>(targetArr.map((i) => [keyFn(i), i]));

    const added: T[] = [];
    const removed: T[] = [];
    const common: T[] = [];

    targetMap.forEach((val, key) => {
      if (!baseMap.has(key)) {
        added.push(val);
      } else {
        common.push(val);
      }
    });

    baseMap.forEach((val, key) => {
      if (!targetMap.has(key)) {
        removed.push(val);
      }
    });

    return { added, removed, common };
  };

  const permissions = diffList(base.permissions || [], target.permissions || []);

  const getExportedNames = (components: { name: string; exported: string | null }[]) =>
    components.filter((c) => c.exported === "true" || c.exported === null).map((c) => c.name);

  const exportedActivities = diffList(
    getExportedNames(base.activities || []),
    getExportedNames(target.activities || [])
  );
  const exportedServices = diffList(
    getExportedNames(base.services || []),
    getExportedNames(target.services || [])
  );
  const exportedReceivers = diffList(
    getExportedNames(base.receivers || []),
    getExportedNames(target.receivers || [])
  );
  const exportedProviders = diffList(
    getExportedNames(base.providers || []),
    getExportedNames(target.providers || [])
  );

  const getTrackerNames = (analysis: APKAnalysis) =>
    (analysis.trackers || []).map((t) => `${t.name} (${t.category})`);

  const trackers = diffList(getTrackerNames(base), getTrackerNames(target));

  // Findings comparison
  const baseFindingTitles = new Set((base.findings || []).map((f) => f.title));
  const targetFindingTitles = new Set((target.findings || []).map((f) => f.title));

  const newCriticalFindings: string[] = (target.findings || [])
    .filter((f) => (f.severity === "critical" || f.severity === "high") && !baseFindingTitles.has(f.title))
    .map((f) => `[${f.severity.toUpperCase()}] ${f.title}`);

  const resolvedFindings: string[] = (base.findings || [])
    .filter((f) => (f.severity === "critical" || f.severity === "high") && !targetFindingTitles.has(f.title))
    .map((f) => `[${f.severity.toUpperCase()}] ${f.title}`);

  const sizeDeltaBytes = target.size - base.size;
  const sizeDeltaPercent = base.size > 0 ? (sizeDeltaBytes / base.size) * 100 : 0;

  const regressionsCount =
    newCriticalFindings.length +
    permissions.added.length +
    exportedActivities.added.length +
    trackers.added.length;

  const improvementsCount = resolvedFindings.length + permissions.removed.length;

  let riskTrend: "increased" | "decreased" | "stable" = "stable";
  if (regressionsCount > improvementsCount) riskTrend = "increased";
  else if (improvementsCount > regressionsCount) riskTrend = "decreased";

  return {
    baseApk: {
      fileName: base.fileName,
      versionName: base.versionName,
      versionCode: base.versionCode,
      size: base.size,
      sha256: base.sha256,
    },
    targetApk: {
      fileName: target.fileName,
      versionName: target.versionName,
      versionCode: target.versionCode,
      size: target.size,
      sha256: target.sha256,
    },
    sizeDeltaBytes,
    sizeDeltaPercent,
    permissions,
    exportedActivities,
    exportedServices,
    exportedReceivers,
    exportedProviders,
    trackers,
    newCriticalFindings,
    resolvedFindings,
    summary: {
      regressionsCount,
      improvementsCount,
      riskTrend,
    },
  };
}
