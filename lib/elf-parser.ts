/**
 * Pure TypeScript ELF (.so) Parser & JNI Symbol Inspector.
 * Extracts ELF Architecture, 32/64-bit class, endianness, imported libraries,
 * and JNI exported function signatures (e.g. Java_com_package_Class_method).
 */

export interface NativeLibraryInfo {
  path: string;
  name: string;
  size: number;
  architecture: string;
  is64Bit: boolean;
  endian: "little" | "big";
  jniFunctions: string[];
  importedLibs: string[];
}

const MACHINE_MAP: Record<number, string> = {
  0x03: "x86 (Intel)",
  0x28: "ARM (armeabi-v7a)",
  0x3E: "x86_64 (AMD64)",
  0xB7: "AArch64 (arm64-v8a)",
  0xF3: "RISC-V",
};

export function parseElf(bytes: Uint8Array, path: string): NativeLibraryInfo {
  const defaultInfo: NativeLibraryInfo = {
    path,
    name: path.split("/").pop() || path,
    size: bytes.byteLength,
    architecture: "Unknown",
    is64Bit: false,
    endian: "little",
    jniFunctions: [],
    importedLibs: [],
  };

  if (bytes.length < 52) return defaultInfo;

  // ELF Magic check: 0x7F, 'E', 'L', 'F'
  if (bytes[0] !== 0x7f || bytes[1] !== 0x45 || bytes[2] !== 0x4c || bytes[3] !== 0x46) {
    return defaultInfo;
  }

  const is64Bit = bytes[4] === 2;
  const isLittleEndian = bytes[5] === 1;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  const e_machine = view.getUint16(18, isLittleEndian);
  const architecture = MACHINE_MAP[e_machine] || `Machine 0x${e_machine.toString(16)}`;

  // Extract JNI exported functions and common dynamic libraries from binary strings
  const text = new TextDecoder("latin1").decode(bytes);
  
  // Find JNI functions matching: Java_<package>_<class>_<method> or JNI_OnLoad
  const jniMatches = text.match(/\b(Java_[a-zA-Z0-9_]+|JNI_OnLoad|JNI_OnUnload)\b/g) || [];
  const uniqueJni = [...new Set(jniMatches)].slice(0, 100);

  // Find linked shared libraries (e.g. libc.so, libm.so, libdl.so, libcrypto.so)
  const libMatches = text.match(/\b(lib[a-zA-Z0-9_\-\.]+\.so)\b/g) || [];
  const ownName = defaultInfo.name;
  const uniqueLibs = [...new Set(libMatches.filter(l => l !== ownName))].slice(0, 30);

  return {
    path,
    name: defaultInfo.name,
    size: bytes.byteLength,
    architecture,
    is64Bit,
    endian: isLittleEndian ? "little" : "big",
    jniFunctions: uniqueJni,
    importedLibs: uniqueLibs,
  };
}
