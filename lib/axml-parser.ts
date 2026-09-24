/**
 * Pure TypeScript Android Binary XML (AXML) Decoder.
 * Decodes compiled AndroidManifest.xml binary format directly into readable XML string
 * and extracts Android manifest metadata, components, permissions, and security flags.
 */

export interface DecodedManifest {
  xml: string;
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
  debuggable: string | null;
  allowBackup: string | null;
  usesCleartextTraffic: string | null;
}

const RES_NULL_TYPE = 0x0000;
const RES_STRING_POOL_TYPE = 0x0001;
const RES_TABLE_TYPE = 0x0002;
const RES_XML_TYPE = 0x0003;
const RES_XML_FIRST_CHUNK_TYPE = 0x0100;
const RES_XML_START_NAMESPACE_TYPE = 0x0100;
const RES_XML_END_NAMESPACE_TYPE = 0x0101;
const RES_XML_START_ELEMENT_TYPE = 0x0102;
const RES_XML_END_ELEMENT_TYPE = 0x0103;
const RES_XML_CDATA_TYPE = 0x0104;
const RES_XML_RESOURCE_MAP_TYPE = 0x0180;

const TYPE_NULL = 0x00;
const TYPE_REFERENCE = 0x01;
const TYPE_ATTRIBUTE = 0x02;
const TYPE_STRING = 0x03;
const TYPE_FLOAT = 0x04;
const TYPE_DIMENSION = 0x05;
const TYPE_FRACTION = 0x06;
const TYPE_DYNAMIC_REFERENCE = 0x07;
const TYPE_INT_DEC = 0x10;
const TYPE_INT_HEX = 0x11;
const TYPE_INT_BOOLEAN = 0x12;
const TYPE_INT_COLOR_ARGB8 = 0x1c;
const TYPE_INT_COLOR_RGB8 = 0x1d;
const TYPE_INT_COLOR_ARGB4 = 0x1e;
const TYPE_INT_COLOR_RGB4 = 0x1f;

interface StringPool {
  strings: string[];
}

function parseStringPool(view: DataView, offset: number): StringPool {
  const headerSize = view.getUint16(offset + 2, true);
  const chunkSize = view.getUint32(offset + 4, true);
  const stringCount = view.getUint32(offset + 8, true);
  const styleCount = view.getUint32(offset + 12, true);
  const flags = view.getUint32(offset + 16, true);
  const stringsStart = view.getUint32(offset + 20, true);

  const isUtf8 = (flags & (1 << 8)) !== 0;

  const stringOffsets: number[] = [];
  for (let i = 0; i < stringCount; i++) {
    stringOffsets.push(view.getUint32(offset + headerSize + i * 4, true));
  }

  const stringsBase = offset + stringsStart;
  const strings: string[] = [];

  for (let i = 0; i < stringCount; i++) {
    const strOffset = stringsBase + stringOffsets[i];
    if (strOffset >= view.byteLength) {
      strings.push("");
      continue;
    }

    if (isUtf8) {
      // UTF-8 length decoding
      let p = strOffset;
      let charLen = view.getUint8(p++);
      if ((charLen & 0x80) !== 0) {
        charLen = ((charLen & 0x7f) << 8) | view.getUint8(p++);
      }
      let byteLen = view.getUint8(p++);
      if ((byteLen & 0x80) !== 0) {
        byteLen = ((byteLen & 0x7f) << 8) | view.getUint8(p++);
      }
      const rawBytes = new Uint8Array(view.buffer, view.byteOffset + p, Math.min(byteLen, view.byteLength - p));
      const str = new TextDecoder("utf-8", { fatal: false }).decode(rawBytes);
      strings.push(str);
    } else {
      // UTF-16LE length decoding
      let p = strOffset;
      let charLen = view.getUint16(p, true);
      p += 2;
      if ((charLen & 0x8000) !== 0) {
        charLen = ((charLen & 0x7fff) << 16) | view.getUint16(p, true);
        p += 2;
      }
      const rawBytes = new Uint8Array(view.buffer, view.byteOffset + p, Math.min(charLen * 2, view.byteLength - p));
      const str = new TextDecoder("utf-16le", { fatal: false }).decode(rawBytes);
      strings.push(str);
    }
  }

  return { strings };
}

function formatValue(type: number, data: number, stringPool: StringPool, rawValueIdx: number): string {
  if (rawValueIdx >= 0 && rawValueIdx < stringPool.strings.length) {
    const raw = stringPool.strings[rawValueIdx];
    if (raw !== null && raw !== undefined && raw !== "") return raw;
  }

  switch (type) {
    case TYPE_STRING:
      return stringPool.strings[data] ?? "";
    case TYPE_INT_BOOLEAN:
      return data !== 0 ? "true" : "false";
    case TYPE_INT_DEC:
      return data.toString();
    case TYPE_INT_HEX:
      return `0x${data.toString(16)}`;
    case TYPE_REFERENCE:
      return `@0x${data.toString(16)}`;
    case TYPE_INT_COLOR_ARGB8:
    case TYPE_INT_COLOR_RGB8:
    case TYPE_INT_COLOR_ARGB4:
    case TYPE_INT_COLOR_RGB4:
      return `#${data.toString(16).padStart(8, "0")}`;
    default:
      return data.toString();
  }
}

export function isBinaryAxml(bytes: Uint8Array): boolean {
  if (bytes.length < 8) return false;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const magic = view.getUint32(0, true);
  // RES_XML_TYPE header: type = 0x0003, headerSize = 0x0008 -> 0x00080003 in 32-bit LE
  return magic === 0x00080003;
}

export function decodeAxml(bytes: Uint8Array): DecodedManifest {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const rootType = view.getUint16(0, true);
  const rootHeaderSize = view.getUint16(2, true);
  const rootChunkSize = view.getUint32(4, true);

  if (rootType !== RES_XML_TYPE) {
    throw new Error("Invalid AXML root type: " + rootType);
  }

  let offset = rootHeaderSize;
  let stringPool: StringPool = { strings: [] };
  const namespaces: Map<string, string> = new Map(); // uri -> prefix

  const xmlLines: string[] = ['<?xml version="1.0" encoding="utf-8"?>'];
  let indent = "";

  let packageName: string | null = null;
  let versionName: string | null = null;
  let versionCode: string | null = null;
  let minSdk: string | null = null;
  let targetSdk: string | null = null;
  const permissions: string[] = [];
  const activities: { name: string; exported: string | null }[] = [];
  const services: { name: string; exported: string | null }[] = [];
  const receivers: { name: string; exported: string | null }[] = [];
  const providers: { name: string; exported: string | null }[] = [];
  let debuggable: string | null = null;
  let allowBackup: string | null = null;
  let usesCleartextTraffic: string | null = null;

  while (offset < view.byteLength && offset < rootChunkSize) {
    const chunkType = view.getUint16(offset, true);
    const headerSize = view.getUint16(offset + 2, true);
    const chunkSize = view.getUint32(offset + 4, true);

    if (chunkSize <= 0) break;

    switch (chunkType) {
      case RES_STRING_POOL_TYPE: {
        stringPool = parseStringPool(view, offset);
        break;
      }

      case RES_XML_RESOURCE_MAP_TYPE: {
        // Resource IDs mapping, skip
        break;
      }

      case RES_XML_START_NAMESPACE_TYPE: {
        const prefixIdx = view.getInt32(offset + 8, true);
        const uriIdx = view.getInt32(offset + 12, true);
        const prefix = prefixIdx >= 0 ? stringPool.strings[prefixIdx] : "";
        const uri = uriIdx >= 0 ? stringPool.strings[uriIdx] : "";
        if (uri) namespaces.set(uri, prefix || "android");
        break;
      }

      case RES_XML_END_NAMESPACE_TYPE: {
        // Namespace scope end
        break;
      }

      case RES_XML_START_ELEMENT_TYPE: {
        const nameIdx = view.getInt32(offset + 20, true);
        const attrStart = view.getUint16(offset + 24, true);
        const attrSize = view.getUint16(offset + 26, true);
        const attrCount = view.getUint16(offset + 28, true);

        const tagName = nameIdx >= 0 ? stringPool.strings[nameIdx] : "unknown";
        const attrs: { name: string; value: string }[] = [];

        let currentAttrOffset = offset + attrStart;
        for (let i = 0; i < attrCount; i++) {
          const attrNsIdx = view.getInt32(currentAttrOffset, true);
          const attrNameIdx = view.getInt32(currentAttrOffset + 4, true);
          const attrRawValueIdx = view.getInt32(currentAttrOffset + 8, true);
          const valType = view.getUint8(currentAttrOffset + 15);
          const valData = view.getUint32(currentAttrOffset + 16, true);

          const attrName = attrNameIdx >= 0 ? stringPool.strings[attrNameIdx] : "";
          const attrNsUri = attrNsIdx >= 0 ? stringPool.strings[attrNsIdx] : "";
          const prefix = attrNsUri ? (namespaces.get(attrNsUri) ?? "android") : "";
          const qualifiedName = prefix ? `${prefix}:${attrName}` : attrName;

          const val = formatValue(valType, valData, stringPool, attrRawValueIdx);
          attrs.push({ name: qualifiedName, value: val });

          currentAttrOffset += attrSize;
        }

        // Add XML namespace definitions to root element
        let nsAttrString = "";
        if (tagName === "manifest") {
          for (const [uri, prefix] of namespaces) {
            nsAttrString += ` xmlns:${prefix}="${uri}"`;
          }
        }

        const attrString = attrs.map(a => ` ${a.name}="${escapeXml(a.value)}"`).join("");
        xmlLines.push(`${indent}<${tagName}${nsAttrString}${attrString}>`);
        indent += "    ";

        // Extract metadata
        const getAttr = (k: string) => attrs.find(a => a.name === `android:${k}` || a.name === k)?.value;

        if (tagName === "manifest") {
          packageName = getAttr("package") ?? attrs.find(a => a.name === "package")?.value ?? null;
          versionName = getAttr("versionName") ?? null;
          versionCode = getAttr("versionCode") ?? null;
        } else if (tagName === "uses-sdk") {
          minSdk = getAttr("minSdkVersion") ?? null;
          targetSdk = getAttr("targetSdkVersion") ?? null;
        } else if (tagName === "uses-permission" || tagName === "uses-permission-sdk-23" || tagName === "uses-permission-sdk-m") {
          const perm = getAttr("name");
          if (perm && !permissions.includes(perm)) permissions.push(perm);
        } else if (tagName === "application") {
          debuggable = getAttr("debuggable") ?? null;
          allowBackup = getAttr("allowBackup") ?? null;
          usesCleartextTraffic = getAttr("usesCleartextTraffic") ?? null;
        } else if (tagName === "activity" || tagName === "activity-alias") {
          const name = getAttr("name");
          if (name) activities.push({ name: normalizeCompName(name, packageName), exported: getAttr("exported") ?? null });
        } else if (tagName === "service") {
          const name = getAttr("name");
          if (name) services.push({ name: normalizeCompName(name, packageName), exported: getAttr("exported") ?? null });
        } else if (tagName === "receiver") {
          const name = getAttr("name");
          if (name) receivers.push({ name: normalizeCompName(name, packageName), exported: getAttr("exported") ?? null });
        } else if (tagName === "provider") {
          const name = getAttr("name");
          if (name) providers.push({ name: normalizeCompName(name, packageName), exported: getAttr("exported") ?? null });
        }

        break;
      }

      case RES_XML_END_ELEMENT_TYPE: {
        const nameIdx = view.getInt32(offset + 20, true);
        const tagName = nameIdx >= 0 ? stringPool.strings[nameIdx] : "unknown";
        indent = indent.slice(0, Math.max(0, indent.length - 4));
        xmlLines.push(`${indent}</${tagName}>`);
        break;
      }

      case RES_XML_CDATA_TYPE: {
        const dataIdx = view.getInt32(offset + 8, true);
        const text = dataIdx >= 0 ? stringPool.strings[dataIdx] : "";
        if (text) xmlLines.push(`${indent}${escapeXml(text)}`);
        break;
      }
    }

    offset += chunkSize;
  }

  return {
    xml: xmlLines.join("\n"),
    packageName,
    versionName,
    versionCode,
    minSdk,
    targetSdk,
    permissions,
    activities,
    services,
    receivers,
    providers,
    debuggable,
    allowBackup,
    usesCleartextTraffic
  };
}

function normalizeCompName(name: string, pkg: string | null): string {
  if (name.startsWith(".")) return `${pkg ?? ""}${name}`;
  if (!name.includes(".") && pkg) return `${pkg}.${name}`;
  return name;
}

function escapeXml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}
