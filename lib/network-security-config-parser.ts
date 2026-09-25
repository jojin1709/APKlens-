/**
 * Pure TypeScript Network Security Configuration Parser.
 * Audits Android 7.0+ network_security_config.xml for cleartext traffic,
 * custom CA trust anchors (MITM risk), and certificate pinning policies.
 */

import { decodeAxml, isBinaryAxml } from "@/lib/axml-parser";

export interface PinEntry {
  digest: string;
  value: string;
}

export interface PinSet {
  expiration?: string;
  domains: { name: string; includeSubdomains: boolean }[];
  pins: PinEntry[];
}

export interface NetworkConfigFinding {
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
}

export interface NetworkSecurityConfigResult {
  present: boolean;
  filePath?: string;
  rawXml?: string;
  cleartextTrafficPermitted: boolean | null;
  trustsUserCerts: boolean;
  trustsSystemCerts: boolean;
  customCertificates: string[];
  pinSets: PinSet[];
  domainConfigs: {
    domains: string[];
    cleartextTrafficPermitted: boolean | null;
    trustsUserCerts: boolean;
  }[];
  findings: NetworkConfigFinding[];
}

export function parseNetworkSecurityConfig(
  fileBytes: Uint8Array,
  filePath: string
): NetworkSecurityConfigResult {
  let xml = "";
  try {
    if (isBinaryAxml(fileBytes)) {
      xml = decodeAxml(fileBytes).xml;
    } else {
      xml = new TextDecoder("utf-8", { fatal: false }).decode(fileBytes);
    }
  } catch {
    return {
      present: true,
      filePath,
      cleartextTrafficPermitted: null,
      trustsUserCerts: false,
      trustsSystemCerts: true,
      customCertificates: [],
      pinSets: [],
      domainConfigs: [],
      findings: [
        {
          severity: "info",
          title: "Network Security Config Detected",
          description: `Config file located at ${filePath} could not be fully parsed.`,
        },
      ],
    };
  }

  const findings: NetworkConfigFinding[] = [];
  let cleartextTrafficPermitted: boolean | null = null;
  let trustsUserCerts = false;
  let trustsSystemCerts = false;
  const customCertificates: string[] = [];
  const pinSets: PinSet[] = [];
  const domainConfigs: {
    domains: string[];
    cleartextTrafficPermitted: boolean | null;
    trustsUserCerts: boolean;
  }[] = [];

  try {
    const parser = new DOMParser();
    const doc = parser.parseFromString(xml, "application/xml");

    // Base-config inspection
    const baseConfig = doc.querySelector("base-config");
    if (baseConfig) {
      const cleartextAttr = baseConfig.getAttribute("cleartextTrafficPermitted");
      if (cleartextAttr !== null) {
        cleartextTrafficPermitted = cleartextAttr.toLowerCase() === "true";
      }

      const certs = baseConfig.querySelectorAll("certificates");
      certs.forEach((c) => {
        const src = c.getAttribute("src");
        if (src === "user") trustsUserCerts = true;
        if (src === "system") trustsSystemCerts = true;
        if (src && src !== "user" && src !== "system") customCertificates.push(src);
      });
    }

    // Domain-config inspection
    const domainConfigNodes = doc.querySelectorAll("domain-config");
    domainConfigNodes.forEach((node) => {
      const domains: string[] = [];
      node.querySelectorAll("domain").forEach((d) => {
        const domainText = d.textContent?.trim() || "";
        if (domainText) domains.push(domainText);
      });

      const cleartextAttr = node.getAttribute("cleartextTrafficPermitted");
      const domainCleartext = cleartextAttr !== null ? cleartextAttr.toLowerCase() === "true" : null;

      let domainUserCerts = false;
      node.querySelectorAll("certificates").forEach((c) => {
        const src = c.getAttribute("src");
        if (src === "user") domainUserCerts = true;
      });

      domainConfigs.push({
        domains,
        cleartextTrafficPermitted: domainCleartext,
        trustsUserCerts: domainUserCerts,
      });

      if (domainCleartext === true) {
        findings.push({
          severity: "high",
          title: `Cleartext HTTP Permitted for ${domains.join(", ") || "Domain"}`,
          description: `Cleartext HTTP communication is explicitly enabled for domain(s): ${domains.join(", ")}. Network traffic is vulnerable to eavesdropping and MITM tampering.`,
        });
      }

      if (domainUserCerts) {
        findings.push({
          severity: "critical",
          title: `User CA Trust Anchor for ${domains.join(", ") || "Domain"}`,
          description: `Domain(s) ${domains.join(", ")} trust user-installed root CAs, allowing proxy tools (Burp Suite, mitmproxy) to intercept TLS traffic without root privilege.`,
        });
      }
    });

    // Pin-set inspection (Certificate Pinning)
    const pinSetNodes = doc.querySelectorAll("pin-set");
    pinSetNodes.forEach((ps) => {
      const expiration = ps.getAttribute("expiration") || undefined;
      const domains: { name: string; includeSubdomains: boolean }[] = [];
      const pins: PinEntry[] = [];

      ps.parentElement?.querySelectorAll("domain").forEach((d) => {
        const name = d.textContent?.trim() || "";
        const inc = d.getAttribute("includeSubdomains")?.toLowerCase() === "true";
        if (name) domains.push({ name, includeSubdomains: inc });
      });

      ps.querySelectorAll("pin").forEach((p) => {
        const digest = p.getAttribute("digest") || "SHA-256";
        const val = p.textContent?.trim() || "";
        if (val) pins.push({ digest, value: val });
      });

      pinSets.push({ expiration, domains, pins });

      if (pins.length > 0) {
        findings.push({
          severity: "info",
          title: `Certificate Pinning Active (${domains.map((d) => d.name).join(", ") || "Configured"})`,
          description: `Configured ${pins.length} public key pins. Enforces strict TLS identity verification.`,
        });
      }
    });

    // Global findings
    if (trustsUserCerts) {
      findings.unshift({
        severity: "critical",
        title: "Global User CA Certificates Trusted",
        description: "The base configuration trusts user-installed certificates. An adversary with device access or a malicious configuration profile can decrypt all application TLS traffic.",
      });
    }

    if (cleartextTrafficPermitted === true) {
      findings.unshift({
        severity: "high",
        title: "Global Cleartext Traffic Allowed",
        description: "The base network security config permits unencrypted HTTP traffic across all endpoints.",
      });
    }
  } catch (err) {
    console.warn("Error parsing network_security_config XML:", err);
  }

  return {
    present: true,
    filePath,
    rawXml: xml,
    cleartextTrafficPermitted,
    trustsUserCerts,
    trustsSystemCerts,
    customCertificates,
    pinSets,
    domainConfigs,
    findings,
  };
}
