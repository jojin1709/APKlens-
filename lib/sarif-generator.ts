import type { APKAnalysis } from "@/types/apk";

/**
 * Generates an OASIS standard SARIF 2.1.0 JSON report from an APKAnalysis.
 * Directly importable into GitHub Security Scanning, GitLab CI/CD, and DefectDojo.
 */
export function generateSarif(analysis: APKAnalysis): string {
  const sarif = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "APKLens",
            version: "2.0.0",
            informationUri: "https://apklens-in.vercel.app/",
            rules: analysis.findings.map((f, i) => ({
              id: `APKLENS-${(i + 1).toString().padStart(3, "0")}`,
              name: f.title,
              shortDescription: { text: f.title },
              fullDescription: { text: f.evidence },
              defaultConfiguration: {
                level: f.severity === "high" ? "error" : f.severity === "medium" ? "warning" : "note"
              }
            }))
          }
        },
        results: analysis.findings.map((f, i) => ({
          ruleId: `APKLENS-${(i + 1).toString().padStart(3, "0")}`,
          level: f.severity === "high" ? "error" : f.severity === "medium" ? "warning" : "note",
          message: {
            text: `${f.title}: ${f.evidence}`
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: analysis.fileName
                }
              }
            }
          ]
        }))
      }
    ]
  };

  return JSON.stringify(sarif, null, 2);
}
