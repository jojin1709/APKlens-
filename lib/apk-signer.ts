/**
 * Pure TypeScript APK Signature and X.509 Certificate Parser.
 * Supports:
 * - APK Signing Scheme v1 (META-INF/*.RSA / *.DSA / *.EC)
 * - APK Signing Scheme v2 / v3 (APK Signing Block)
 * - X.509 Certificate extraction & metadata parsing (Subject, Issuer, Validity, Fingerprints, Alg)
 */

export interface APKCertificate {
  scheme: "v1 (JAR)" | "v2 (Signing Block)" | "v3 (Signing Block)";
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  sigAlg: string;
  serialNumber: string;
  sha1Fingerprint: string;
  sha256Fingerprint: string;
}

// OID map for common X.509 attributes & algorithms
const OID_NAMES: Record<string, string> = {
  "2.5.4.3": "CN",
  "2.5.4.10": "O",
  "2.5.4.11": "OU",
  "2.5.4.6": "C",
  "2.5.4.7": "L",
  "2.5.4.8": "ST",
  "2.5.4.9": "STREET",
  "1.2.840.113549.1.1.1": "RSA Encryption",
  "1.2.840.113549.1.1.5": "SHA-1 with RSA",
  "1.2.840.113549.1.1.11": "SHA-256 with RSA",
  "1.2.840.113549.1.1.12": "SHA-384 with RSA",
  "1.2.840.113549.1.1.13": "SHA-512 with RSA",
  "1.2.840.10045.2.1": "EC Public Key",
  "1.2.840.10045.4.3.2": "SHA-256 with ECDSA",
  "1.2.840.10040.4.1": "DSA",
  "1.2.840.10040.4.3": "SHA-1 with DSA",
};

interface Asn1Node {
  tag: number;
  headerLen: number;
  length: number;
  offset: number;
  raw: Uint8Array;
}

function parseAsn1(bytes: Uint8Array, offset = 0): Asn1Node | null {
  if (offset >= bytes.length) return null;
  const tag = bytes[offset];
  let p = offset + 1;
  if (p >= bytes.length) return null;

  let length = bytes[p++];
  if ((length & 0x80) !== 0) {
    const numBytes = length & 0x7f;
    if (numBytes > 4 || p + numBytes > bytes.length) return null;
    length = 0;
    for (let i = 0; i < numBytes; i++) {
      length = (length << 8) | bytes[p++];
    }
  }

  const headerLen = p - offset;
  const end = p + length;
  if (end > bytes.length) return null;

  return {
    tag,
    headerLen,
    length,
    offset,
    raw: bytes.subarray(p, end)
  };
}

function parseChildren(bytes: Uint8Array): Asn1Node[] {
  const children: Asn1Node[] = [];
  let p = 0;
  while (p < bytes.length) {
    const node = parseAsn1(bytes, p);
    if (!node) break;
    children.push(node);
    p += node.headerLen + node.length;
  }
  return children;
}

function readOid(bytes: Uint8Array): string {
  if (!bytes.length) return "";
  const parts: number[] = [Math.floor(bytes[0] / 40), bytes[0] % 40];
  let val = 0;
  for (let i = 1; i < bytes.length; i++) {
    val = (val << 7) | (bytes[i] & 0x7f);
    if ((bytes[i] & 0x80) === 0) {
      parts.push(val);
      val = 0;
    }
  }
  const oid = parts.join(".");
  return OID_NAMES[oid] ?? oid;
}

function readRdnString(node: Asn1Node): string {
  // UTF8String (0x0C), PrintableString (0x13), IA5String (0x16), TeletexString (0x14)
  try {
    return new TextDecoder("utf-8", { fatal: false }).decode(node.raw);
  } catch {
    return "";
  }
}

function parseRdnSequence(bytes: Uint8Array): string {
  const parts: string[] = [];
  const sets = parseChildren(bytes);
  for (const set of sets) {
    const seqs = parseChildren(set.raw);
    for (const seq of seqs) {
      const items = parseChildren(seq.raw);
      if (items.length >= 2) {
        const oid = readOid(items[0].raw);
        const val = readRdnString(items[1]);
        if (oid && val) parts.push(`${oid}=${val}`);
      }
    }
  }
  return parts.join(", ") || "Unknown";
}

function parseTime(node: Asn1Node): string {
  // UTCTime (0x17) YYMMDDHHMMSSZ or GeneralizedTime (0x18) YYYYMMDDHHMMSSZ
  const rawStr = new TextDecoder("ascii").decode(node.raw);
  try {
    if (node.tag === 0x17 && rawStr.length >= 12) {
      let year = parseInt(rawStr.slice(0, 2), 10);
      year += year >= 50 ? 1900 : 2000;
      const month = rawStr.slice(2, 4);
      const day = rawStr.slice(4, 6);
      const hour = rawStr.slice(6, 8);
      const min = rawStr.slice(8, 10);
      const sec = rawStr.slice(10, 12);
      return new Date(Date.UTC(year, parseInt(month, 10) - 1, parseInt(day, 10), parseInt(hour, 10), parseInt(min, 10), parseInt(sec, 10))).toUTCString();
    } else if (node.tag === 0x18 && rawStr.length >= 14) {
      const year = parseInt(rawStr.slice(0, 4), 10);
      const month = rawStr.slice(4, 6);
      const day = rawStr.slice(6, 8);
      const hour = rawStr.slice(8, 10);
      const min = rawStr.slice(10, 12);
      const sec = rawStr.slice(12, 14);
      return new Date(Date.UTC(year, parseInt(month, 10) - 1, parseInt(day, 10), parseInt(hour, 10), parseInt(min, 10), parseInt(sec, 10))).toUTCString();
    }
  } catch {
    // fallback
  }
  return rawStr;
}

async function computeFingerprint(bytes: Uint8Array, algo: "SHA-256" | "SHA-1"): Promise<string> {
  const copy = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  const hash = await crypto.subtle.digest(algo, copy as ArrayBuffer);
  return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, "0").toUpperCase()).join(":");
}

export async function parseX509Certificate(certBytes: Uint8Array, scheme: APKCertificate["scheme"]): Promise<APKCertificate | null> {
  try {
    const root = parseAsn1(certBytes);
    if (!root || root.tag !== 0x30) return null; // Must be SEQUENCE

    const certChildren = parseChildren(root.raw);
    if (certChildren.length < 3) return null;

    const tbsNode = certChildren[0];
    if (tbsNode.tag !== 0x30) return null;

    const tbsChildren = parseChildren(tbsNode.raw);
    let idx = 0;

    // Optional version [0] EXPLICIT
    if (tbsChildren[idx] && tbsChildren[idx].tag === 0xa0) {
      idx++;
    }

    // Serial number (INTEGER 0x02)
    const serialNode = tbsChildren[idx++];
    const serialNumber = serialNode ? [...serialNode.raw].map(b => b.toString(16).padStart(2, "0")).join("") : "Unknown";

    // Signature algorithm
    const sigAlgNode = tbsChildren[idx++];
    let sigAlg = "Unknown";
    if (sigAlgNode) {
      const sigAlgChildren = parseChildren(sigAlgNode.raw);
      if (sigAlgChildren[0]) sigAlg = readOid(sigAlgChildren[0].raw);
    }

    // Issuer
    const issuerNode = tbsChildren[idx++];
    const issuer = issuerNode ? parseRdnSequence(issuerNode.raw) : "Unknown";

    // Validity
    const validityNode = tbsChildren[idx++];
    let validFrom = "Unknown";
    let validTo = "Unknown";
    if (validityNode) {
      const times = parseChildren(validityNode.raw);
      if (times[0]) validFrom = parseTime(times[0]);
      if (times[1]) validTo = parseTime(times[1]);
    }

    // Subject
    const subjectNode = tbsChildren[idx++];
    const subject = subjectNode ? parseRdnSequence(subjectNode.raw) : "Unknown";

    const sha256Fingerprint = await computeFingerprint(certBytes, "SHA-256");
    const sha1Fingerprint = await computeFingerprint(certBytes, "SHA-1");

    return {
      scheme,
      subject,
      issuer,
      validFrom,
      validTo,
      sigAlg,
      serialNumber,
      sha1Fingerprint,
      sha256Fingerprint
    };
  } catch (e) {
    console.error("Failed to parse X.509 cert:", e);
    return null;
  }
}

/**
 * Extracts and parses certificate from APK v1 signature files (META-INF/*.RSA or *.DSA or *.EC).
 * These files contain PKCS#7 SignedData containing the X.509 certificate.
 */
export async function parseV1Signature(pkcs7Bytes: Uint8Array): Promise<APKCertificate | null> {
  try {
    // Traverse ASN.1 to find X.509 Certificate (tag 0x30 with sub-SEQUENCE containing validity/subject)
    const root = parseAsn1(pkcs7Bytes);
    if (!root) return null;

    // Scan for embedded X.509 certificate sequence
    // A standard certificate starts with SEQUENCE { SEQUENCE { ... } ... }
    const queue = [root];
    while (queue.length) {
      const node = queue.shift()!;
      if (node.tag === 0x30 && node.length > 200) {
        const sub = parseChildren(node.raw);
        if (sub.length >= 3 && sub[0].tag === 0x30 && (sub[1].tag === 0x30 || sub[1].tag === 0x06)) {
          // Candidate X.509 certificate
          const certBytes = pkcs7Bytes.subarray(node.offset, node.offset + node.headerLen + node.length);
          const parsed = await parseX509Certificate(certBytes, "v1 (JAR)");
          if (parsed && parsed.subject !== "Unknown") {
            return parsed;
          }
        }
      }

      if ((node.tag & 0x20) !== 0 || node.tag === 0x30 || node.tag === 0x31 || (node.tag >= 0xa0 && node.tag <= 0xbf)) {
        queue.push(...parseChildren(node.raw));
      }
    }
  } catch {
    // continue
  }
  return null;
}

/**
 * Scans APK buffer for the APK Signing Block (Scheme v2 and v3).
 * Magic: "APK Sig Block 42" (16 bytes) preceding Central Directory.
 */
export async function parseV2V3Signature(buffer: ArrayBuffer): Promise<APKCertificate | null> {
  const bytes = new Uint8Array(buffer);
  const view = new DataView(buffer);

  // Magic bytes: 'A','P','K',' ','S','i','g',' ','B','l','o','c','k',' ','4','2'
  const magic = [0x41, 0x50, 0x4b, 0x20, 0x53, 0x69, 0x67, 0x20, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x34, 0x32];

  // Scan backwards from end for End of Central Directory Record (EOCD: 0x06054b50)
  let eocdOffset = -1;
  const maxScan = Math.min(65536 + 22, bytes.length);
  for (let i = bytes.length - 22; i >= bytes.length - maxScan; i--) {
    if (view.getUint32(i, true) === 0x06054b50) {
      eocdOffset = i;
      break;
    }
  }
  if (eocdOffset === -1) return null;

  // Central directory offset is at eocdOffset + 16
  const cdOffset = view.getUint32(eocdOffset + 16, true);
  if (cdOffset < 24) return null;

  // Check magic 16 bytes immediately before cdOffset
  const blockMagicOffset = cdOffset - 16;
  for (let i = 0; i < 16; i++) {
    if (bytes[blockMagicOffset + i] !== magic[i]) return null;
  }

  // Size of block (uint64 at blockMagicOffset - 8)
  const blockSizeLow = view.getUint32(blockMagicOffset - 8, true);
  const blockStart = cdOffset - 8 - blockSizeLow;
  if (blockStart < 0) return null;

  // Verify size at start matches
  const sizeStart = view.getUint32(blockStart, true);
  if (sizeStart !== blockSizeLow) return null;

  // Iterate ID-value pairs
  let p = blockStart + 8;
  const end = blockMagicOffset - 8;

  while (p < end) {
    const pairLen = view.getUint32(p, true);
    p += 8;
    const pairId = view.getUint32(p, true);
    p += 4;
    const valLen = pairLen - 4;

    // ID 0x7109871a = v2, ID 0xf05368c0 = v3
    if (pairId === 0x7109871a || pairId === 0xf05368c0) {
      const scheme: APKCertificate["scheme"] = pairId === 0xf05368c0 ? "v3 (Signing Block)" : "v2 (Signing Block)";
      const pairBytes = bytes.subarray(p, p + valLen);

      // Extract certificate from signers sequence
      // Structure: length-prefixed sequence of signers -> signed data -> certificates
      try {
        const pairView = new DataView(pairBytes.buffer, pairBytes.byteOffset, pairBytes.byteLength);
        let cur = 4; // skip signers sequence len
        if (cur < pairBytes.length) {
          const signerLen = pairView.getUint32(cur, true);
          cur += 4;
          const signedDataLen = pairView.getUint32(cur, true);
          cur += 4;
          // Inside signedData: digests len -> skip digests
          const digestsLen = pairView.getUint32(cur, true);
          cur += 4 + digestsLen;
          // Certificates sequence
          const certsLen = pairView.getUint32(cur, true);
          cur += 4;
          if (certsLen > 0 && cur < pairBytes.length) {
            const firstCertLen = pairView.getUint32(cur, true);
            cur += 4;
            const certBytes = pairBytes.subarray(cur, cur + firstCertLen);
            const parsed = await parseX509Certificate(certBytes, scheme);
            if (parsed) return parsed;
          }
        }
      } catch {
        // continue
      }
    }
    p += valLen;
  }

  return null;
}
