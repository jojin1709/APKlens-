/**
 * Pure TypeScript ELF (.so) Parser, JNI Symbol Inspector & Binary Hardening Auditor.
 * Extracts ELF Architecture, 32/64-bit class, endianness, imported libraries,
 * JNI exported function signatures, and checks compiler security hardening:
 * - PIE (Position Independent Executable)
 * - Stack Canary (__stack_chk_fail)
 * - NX Stack (PT_GNU_STACK without execute flag)
 * - RELRO (PT_GNU_RELRO)
 * - FORTIFY_SOURCE (__*_chk library functions)
 * - RPATH / RUNPATH binary search paths
 */

export interface ElfHardeningInfo {
  hasPie: boolean;
  hasStackCanary: boolean;
  hasNxStack: boolean;
  hasRelro: boolean;
  hasFortify: boolean;
  hasRpath: boolean;
  rpathEntries: string[];
}

export interface NativeLibraryInfo {
  path: string;
  name: string;
  size: number;
  architecture: string;
  is64Bit: boolean;
  endian: "little" | "big";
  jniFunctions: string[];
  importedLibs: string[];
  hardening: ElfHardeningInfo;
}

const MACHINE_MAP: Record<number, string> = {
  0x03: "x86 (Intel)",
  0x28: "ARM (armeabi-v7a)",
  0x3e: "x86_64 (AMD64)",
  0xb7: "AArch64 (arm64-v8a)",
  0xf3: "RISC-V",
};

const PT_GNU_STACK = 0x6474e551;
const PT_GNU_RELRO = 0x6474e552;

export function parseElf(bytes: Uint8Array, path: string): NativeLibraryInfo {
  const defaultHardening: ElfHardeningInfo = {
    hasPie: false,
    hasStackCanary: false,
    hasNxStack: false,
    hasRelro: false,
    hasFortify: false,
    hasRpath: false,
    rpathEntries: [],
  };

  const defaultInfo: NativeLibraryInfo = {
    path,
    name: path.split("/").pop() || path,
    size: bytes.byteLength,
    architecture: "Unknown",
    is64Bit: false,
    endian: "little",
    jniFunctions: [],
    importedLibs: [],
    hardening: defaultHardening,
  };

  if (bytes.length < 52) return defaultInfo;

  // ELF Magic check: 0x7F, 'E', 'L', 'F'
  if (bytes[0] !== 0x7f || bytes[1] !== 0x45 || bytes[2] !== 0x4c || bytes[3] !== 0x46) {
    return defaultInfo;
  }

  const is64Bit = bytes[4] === 2;
  const isLittleEndian = bytes[5] === 1;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  // e_type: ET_DYN (3) = shared library / position independent executable
  const e_type = view.getUint16(16, isLittleEndian);
  const hasPie = e_type === 3;

  const e_machine = view.getUint16(18, isLittleEndian);
  const architecture = MACHINE_MAP[e_machine] || `Machine 0x${e_machine.toString(16)}`;

  // Program header parsing for NX Stack and RELRO
  let hasNxStack = false;
  let hasRelro = false;

  try {
    let phOff = 0;
    let phEntSize = 0;
    let phNum = 0;

    if (is64Bit) {
      if (bytes.length >= 64) {
        phOff = Number(view.getBigUint64(32, isLittleEndian));
        phEntSize = view.getUint16(54, isLittleEndian);
        phNum = view.getUint16(56, isLittleEndian);
      }
    } else {
      phOff = view.getUint32(28, isLittleEndian);
      phEntSize = view.getUint16(42, isLittleEndian);
      phNum = view.getUint16(44, isLittleEndian);
    }

    if (phOff > 0 && phEntSize >= 32 && phNum > 0 && phOff + phNum * phEntSize <= bytes.byteLength) {
      for (let i = 0; i < phNum; i++) {
        const entryOff = phOff + i * phEntSize;
        const p_type = view.getUint32(entryOff, isLittleEndian);

        if (p_type === PT_GNU_STACK) {
          // p_flags is at offset 4 in 64-bit or offset 24 in 32-bit
          const flagsOff = is64Bit ? entryOff + 4 : entryOff + 24;
          const p_flags = view.getUint32(flagsOff, isLittleEndian);
          // PF_X = 0x1. If executable bit is 0, stack is non-executable
          hasNxStack = (p_flags & 0x1) === 0;
        } else if (p_type === PT_GNU_RELRO) {
          hasRelro = true;
        }
      }
    }
  } catch (err) {
    console.warn("Error reading ELF program headers:", err);
  }

  // Extract binary strings to find JNI functions, linked libraries, and symbol hardening
  const text = new TextDecoder("latin1").decode(bytes);

  // Stack Canary check
  const hasStackCanary =
    text.includes("__stack_chk_fail") ||
    text.includes("__stack_chk_guard") ||
    text.includes("__intel_security_cookie");

  // FORTIFY_SOURCE check
  const hasFortify =
    text.includes("__memcpy_chk") ||
    text.includes("__snprintf_chk") ||
    text.includes("__sprintf_chk") ||
    text.includes("__strncpy_chk") ||
    text.includes("__vsnprintf_chk") ||
    text.includes("__memmove_chk") ||
    text.includes("__memset_chk") ||
    text.includes("__strcat_chk") ||
    text.includes("__strcpy_chk");

  // RPATH / RUNPATH check
  const rpathMatches = text.match(/(?:\$ORIGIN[a-zA-Z0-9_\-\.\/]*)|(?:\/(?:data|tmp|cache)[a-zA-Z0-9_\-\.\/]*)/g) || [];
  const uniqueRpaths = [...new Set(rpathMatches)].slice(0, 5);
  const hasRpath = uniqueRpaths.length > 0;

  // JNI exported function signatures
  const jniMatches = text.match(/\b(Java_[a-zA-Z0-9_]+|JNI_OnLoad|JNI_OnUnload)\b/g) || [];
  const uniqueJni = [...new Set(jniMatches)].slice(0, 100);

  // Find linked shared libraries (e.g. libc.so, libm.so, libdl.so, libcrypto.so)
  const libMatches = text.match(/\b(lib[a-zA-Z0-9_\-\.]+\.so)\b/g) || [];
  const ownName = defaultInfo.name;
  const uniqueLibs = [...new Set(libMatches.filter((l) => l !== ownName))].slice(0, 30);

  return {
    path,
    name: defaultInfo.name,
    size: bytes.byteLength,
    architecture,
    is64Bit,
    endian: isLittleEndian ? "little" : "big",
    jniFunctions: uniqueJni,
    importedLibs: uniqueLibs,
    hardening: {
      hasPie,
      hasStackCanary,
      hasNxStack,
      hasRelro,
      hasFortify,
      hasRpath,
      rpathEntries: uniqueRpaths,
    },
  };
}
