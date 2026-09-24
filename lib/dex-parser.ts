/**
 * Lightweight pure TypeScript Dalvik DEX Parser.
 * Extracts class descriptor names, class count, method count, and string IDs
 * directly from classes.dex headers without external runtimes.
 */

export interface DexInfo {
  path: string;
  size: number;
  classCount: number;
  methodCount: number;
  classes: string[];
}

export function parseDex(bytes: Uint8Array, path: string): DexInfo {
  if (bytes.length < 0x70) {
    return { path, size: bytes.length, classCount: 0, methodCount: 0, classes: [] };
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  // Check magic 'dex\n'
  const isDex = bytes[0] === 0x64 && bytes[1] === 0x65 && bytes[2] === 0x78 && bytes[3] === 0x0a;
  if (!isDex) {
    return { path, size: bytes.length, classCount: 0, methodCount: 0, classes: [] };
  }

  const stringIdsSize = view.getUint32(0x38, true);
  const stringIdsOff = view.getUint32(0x3c, true);
  const typeIdsSize = view.getUint32(0x40, true);
  const typeIdsOff = view.getUint32(0x44, true);
  const methodIdsSize = view.getUint32(0x58, true);
  const classDefsSize = view.getUint32(0x60, true);
  const classDefsOff = view.getUint32(0x64, true);

  // Function to read a MUTF-8 string by string_id index
  const readString = (idx: number): string => {
    if (idx >= stringIdsSize) return "";
    const strDataOff = view.getUint32(stringIdsOff + idx * 4, true);
    if (strDataOff >= bytes.length) return "";

    // Read uleb128 utf16_size
    let p = strDataOff;
    let utf16Size = 0;
    let shift = 0;
    while (p < bytes.length) {
      const b = bytes[p++];
      utf16Size |= (b & 0x7f) << shift;
      if ((b & 0x80) === 0) break;
      shift += 7;
    }

    // Read null-terminated MUTF-8
    let end = p;
    while (end < bytes.length && bytes[end] !== 0) {
      end++;
    }
    const raw = bytes.subarray(p, end);
    return new TextDecoder("utf-8", { fatal: false }).decode(raw);
  };

  // Function to read a type_id (which points to a string_id)
  const readType = (typeIdx: number): string => {
    if (typeIdx >= typeIdsSize) return "";
    const strIdx = view.getUint32(typeIdsOff + typeIdx * 4, true);
    return readString(strIdx);
  };

  // Read class definitions
  const classes: string[] = [];
  const limit = Math.min(classDefsSize, 1000); // Read up to 1000 classes for snappy UI performance
  for (let i = 0; i < limit; i++) {
    const classDefOffset = classDefsOff + i * 32;
    if (classDefOffset + 32 > bytes.length) break;

    const classIdx = view.getUint32(classDefOffset, true);
    const rawDescriptor = readType(classIdx);
    if (rawDescriptor.startsWith("L") && rawDescriptor.endsWith(";")) {
      const formatted = rawDescriptor.slice(1, -1).replace(/\//g, ".");
      classes.push(formatted);
    }
  }

  return {
    path,
    size: bytes.length,
    classCount: classDefsSize,
    methodCount: methodIdsSize,
    classes
  };
}
