/**
 * Pure TypeScript Client-Side Dalvik DEX Disassembler.
 * Decodes DEX class_def, class_data, code_item, and Dalvik bytecode opcodes
 * directly in the browser into clean Smali-style disassembled source.
 */

export interface DisassembledMethod {
  name: string;
  signature: string;
  accessFlags: string;
  registers: number;
  instructions: string[];
}

export interface DisassembledClass {
  className: string;
  superClass: string;
  sourceFile?: string;
  fields: string[];
  methods: DisassembledMethod[];
  smaliCode: string;
}

// Common Dalvik Opcodes mapping
const DALVIK_OPCODES: Record<number, string> = {
  0x00: "nop",
  0x01: "move",
  0x02: "move/from16",
  0x03: "move/16",
  0x04: "move-wide",
  0x05: "move-wide/from16",
  0x06: "move-wide/16",
  0x07: "move-object",
  0x08: "move-object/from16",
  0x09: "move-object/16",
  0x0a: "move-result",
  0x0b: "move-result-wide",
  0x0c: "move-result-object",
  0x0d: "move-exception",
  0x0e: "return-void",
  0x0f: "return",
  0x10: "return-wide",
  0x11: "return-object",
  0x12: "const/4",
  0x13: "const/16",
  0x14: "const",
  0x15: "const/high16",
  0x16: "const-wide/16",
  0x17: "const-wide/32",
  0x18: "const-wide",
  0x19: "const-wide/high16",
  0x1a: "const-string",
  0x1b: "const-string/jumbo",
  0x1c: "const-class",
  0x1d: "monitor-enter",
  0x1e: "monitor-exit",
  0x1f: "check-cast",
  0x20: "instance-of",
  0x21: "array-length",
  0x22: "new-instance",
  0x23: "new-array",
  0x24: "filled-new-array",
  0x25: "filled-new-array/range",
  0x26: "fill-array-data",
  0x27: "throw",
  0x28: "goto",
  0x29: "goto/16",
  0x2a: "goto/32",
  0x32: "if-eq",
  0x33: "if-ne",
  0x34: "if-lt",
  0x35: "if-ge",
  0x36: "if-gt",
  0x37: "if-le",
  0x38: "if-eqz",
  0x39: "if-nez",
  0x3a: "if-ltz",
  0x3b: "if-gez",
  0x3c: "if-gtz",
  0x3d: "if-lez",
  0x52: "iget",
  0x53: "iget-wide",
  0x54: "iget-object",
  0x55: "iget-boolean",
  0x56: "iget-byte",
  0x57: "iget-char",
  0x58: "iget-short",
  0x59: "iput",
  0x5a: "iput-wide",
  0x5b: "iput-object",
  0x60: "sget",
  0x61: "sget-wide",
  0x62: "sget-object",
  0x67: "sput",
  0x68: "sput-wide",
  0x69: "sput-object",
  0x6e: "invoke-virtual",
  0x6f: "invoke-super",
  0x70: "invoke-direct",
  0x71: "invoke-static",
  0x72: "invoke-interface",
  0x74: "invoke-virtual/range",
  0x75: "invoke-super/range",
  0x76: "invoke-direct/range",
  0x77: "invoke-static/range",
  0x78: "invoke-interface/range",
};

/**
 * Disassemble a target class from raw DEX bytecode directly in the browser.
 */
export function disassembleDexClass(
  dexBytes: Uint8Array,
  targetClassName: string
): DisassembledClass {
  const cleanTarget = targetClassName.replace(/^L|;$/g, "").replace(/\./g, "/");
  const cleanDots = cleanTarget.replace(/\//g, ".");

  const view = new DataView(dexBytes.buffer, dexBytes.byteOffset, dexBytes.byteLength);

  // Read DEX Header
  const stringIdsSize = view.getUint32(0x38, true);
  const stringIdsOff = view.getUint32(0x3c, true);
  const typeIdsSize = view.getUint32(0x40, true);
  const typeIdsOff = view.getUint32(0x44, true);
  const protoIdsSize = view.getUint32(0x48, true);
  const protoIdsOff = view.getUint32(0x4c, true);
  const methodIdsSize = view.getUint32(0x58, true);
  const methodIdsOff = view.getUint32(0x5c, true);
  const classDefsSize = view.getUint32(0x60, true);
  const classDefsOff = view.getUint32(0x64, true);

  // Helper: Read MUTF-8 string
  const readString = (idx: number): string => {
    if (idx >= stringIdsSize) return "";
    const strDataOff = view.getUint32(stringIdsOff + idx * 4, true);
    if (strDataOff >= dexBytes.length) return "";

    let p = strDataOff;
    while (p < dexBytes.length && (dexBytes[p++] & 0x80) !== 0) {}
    let end = p;
    while (end < dexBytes.length && dexBytes[end] !== 0) end++;
    return new TextDecoder("utf-8", { fatal: false }).decode(dexBytes.subarray(p, end));
  };

  const readType = (idx: number): string => {
    if (idx >= typeIdsSize) return "";
    return readString(view.getUint32(typeIdsOff + idx * 4, true));
  };

  const readMethodName = (mIdx: number): string => {
    if (mIdx >= methodIdsSize) return `method_${mIdx}`;
    const nameIdx = view.getUint32(methodIdsOff + mIdx * 8 + 4, true);
    return readString(nameIdx);
  };

  // Find target class_def_item
  let targetClassDefOffset = -1;
  let superClass = "java.lang.Object";

  for (let i = 0; i < classDefsSize; i++) {
    const off = classDefsOff + i * 32;
    if (off + 32 > dexBytes.length) break;
    const classIdx = view.getUint32(off, true);
    const rawDesc = readType(classIdx);
    const normalized = rawDesc.replace(/^L|;$/g, "");
    if (normalized === cleanTarget || normalized === cleanDots) {
      targetClassDefOffset = off;
      const superIdx = view.getUint32(off + 4, true);
      superClass = readType(superIdx).replace(/^L|;$/g, "").replace(/\//g, ".") || "java.lang.Object";
      break;
    }
  }

  const methods: DisassembledMethod[] = [];
  const fields: string[] = [];

  // Read class_data_off
  if (targetClassDefOffset !== -1) {
    const classDataOff = view.getUint32(targetClassDefOffset + 24, true);
    if (classDataOff > 0 && classDataOff < dexBytes.length) {
      let p = classDataOff;
      const readUleb = (): number => {
        let res = 0, shift = 0;
        while (p < dexBytes.length) {
          const b = dexBytes[p++];
          res |= (b & 0x7f) << shift;
          if ((b & 0x80) === 0) break;
          shift += 7;
        }
        return res;
      };

      const staticFieldsSize = readUleb();
      const instanceFieldsSize = readUleb();
      const directMethodsSize = readUleb();
      const virtualMethodsSize = readUleb();

      // Skip fields
      for (let i = 0; i < staticFieldsSize + instanceFieldsSize; i++) {
        readUleb(); // field_idx_diff
        readUleb(); // access_flags
      }

      // Read methods
      const totalMethods = directMethodsSize + virtualMethodsSize;
      let prevMethodIdx = 0;
      for (let i = 0; i < totalMethods; i++) {
        const methodIdxDiff = readUleb();
        prevMethodIdx += methodIdxDiff;
        const accessFlags = readUleb();
        const codeOff = readUleb();

        const methodName = readMethodName(prevMethodIdx);
        const methodInstructions: string[] = [];
        let registers = 2;

        if (codeOff > 0 && codeOff + 16 < dexBytes.length) {
          registers = view.getUint16(codeOff, true);
          const insnsSize = view.getUint32(codeOff + 12, true);
          const insnsStart = codeOff + 16;
          const insnsLimit = Math.min(insnsSize, 250); // limit to 250 instructions per method for speed

          for (let pc = 0; pc < insnsLimit && insnsStart + pc * 2 + 2 <= dexBytes.length; ) {
            const rawInsn = view.getUint16(insnsStart + pc * 2, true);
            const opcode = rawInsn & 0xff;
            const opName = DALVIK_OPCODES[opcode] || `op_${opcode.toString(16).padStart(2, "0")}`;

            // Parse common register formats
            const vA = (rawInsn >> 8) & 0x0f;
            const vB = (rawInsn >> 12) & 0x0f;

            if (opcode === 0x1a && pc + 1 < insnsLimit) { // const-string
              const strIdx = view.getUint16(insnsStart + (pc + 1) * 2, true);
              const val = readString(strIdx);
              methodInstructions.push(`    ${opName} v${(rawInsn >> 8) & 0xff}, "${val.slice(0, 50).replace(/"/g, '\\"')}"`);
              pc += 2;
            } else if (opcode >= 0x6e && opcode <= 0x72 && pc + 1 < insnsLimit) { // invoke-*
              const targetM = view.getUint16(insnsStart + (pc + 1) * 2, true);
              const calledName = readMethodName(targetM);
              methodInstructions.push(`    ${opName} {v${vA}..v${vB}}, ->${calledName}()`);
              pc += 3;
            } else if (opcode === 0x0e) { // return-void
              methodInstructions.push(`    return-void`);
              pc += 1;
            } else {
              methodInstructions.push(`    ${opName} v${vA}, v${vB}`);
              pc += 1;
            }
          }
        }

        const isStatic = (accessFlags & 0x0008) !== 0;
        const isPublic = (accessFlags & 0x0001) !== 0;
        const accessStr = `${isPublic ? "public " : "private "}${isStatic ? "static " : ""}`.trim();

        methods.push({
          name: methodName,
          signature: "()V",
          accessFlags: accessStr,
          registers,
          instructions: methodInstructions.length > 0 ? methodInstructions : ["    return-void"],
        });
      }
    }
  }

  // Generate Smali output
  let smali = `.class public L${cleanTarget};\n`;
  smali += `.super L${superClass.replace(/\./g, "/")};\n\n`;
  smali += `# Disassembled via APKLens In-Browser Dalvik Disassembler\n`;
  smali += `# Total Methods: ${methods.length}\n\n`;

  for (const m of methods) {
    smali += `.method ${m.accessFlags} ${m.name}${m.signature}\n`;
    smali += `    .registers ${m.registers}\n`;
    smali += m.instructions.join("\n") + "\n";
    smali += `.end method\n\n`;
  }

  return {
    className: cleanDots,
    superClass,
    fields,
    methods,
    smaliCode: smali,
  };
}
