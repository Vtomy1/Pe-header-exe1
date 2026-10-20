/**
 * Windows PE (Portable Executable) Parser
 * Spec compliant with Microsoft PE and COFF Specification (v8.3+)
 */

export interface ByteSpan {
  start: number;
  end: number;
  name: string;
  category: 'dos' | 'dos_stub' | 'rich' | 'nt_sig' | 'file_header' | 'optional_header' | 'data_dirs' | 'section_headers' | 'section_data' | 'export_dir' | 'other';
  description?: string;
  valueStr?: string;
}

export interface DosHeader {
  e_magic: number; // 0x5A4D ('MZ')
  e_cblp: number;
  e_cp: number;
  e_crlc: number;
  e_cparhdr: number;
  e_minalloc: number;
  e_maxalloc: number;
  e_ss: number;
  e_sp: number;
  e_csum: number;
  e_ip: number;
  e_cs: number;
  e_lfarlc: number;
  e_ovno: number;
  e_res: number[];
  e_oemid: number;
  e_oeminfo: number;
  e_res2: number[];
  e_lfanew: number; // Offset to PE header
}

export interface RichHeaderEntry {
  toolId: number;
  toolName: string;
  buildId: number;
  vsVersion: string;
  count: number;
}

export interface RichHeader {
  offset: number;
  size: number;
  xorKey: number;
  entries: RichHeaderEntry[];
}

export interface FileHeader {
  machine: number;
  machineName: string;
  numberOfSections: number;
  timeDateStamp: number;
  timeDateString: string;
  pointerToSymbolTable: number;
  numberOfSymbols: number;
  sizeOfOptionalHeader: number;
  characteristics: number;
  characteristicsList: string[];
}

export interface DataDirectory {
  index: number;
  name: string;
  virtualAddress: number;
  size: number;
  sectionName?: string;
}

export interface OptionalHeader {
  magic: number; // 0x10B = PE32, 0x20B = PE32+
  is64Bit: boolean;
  majorLinkerVersion: number;
  minorLinkerVersion: number;
  sizeOfCode: number;
  sizeOfInitializedData: number;
  sizeOfUninitializedData: number;
  addressOfEntryPoint: number;
  baseOfCode: number;
  baseOfData?: number; // 32-bit only
  imageBase: string;
  sectionAlignment: number;
  fileAlignment: number;
  majorOperatingSystemVersion: number;
  minorOperatingSystemVersion: number;
  majorImageVersion: number;
  minorImageVersion: number;
  majorSubsystemVersion: number;
  minorSubsystemVersion: number;
  win32VersionValue: number;
  sizeOfImage: number;
  sizeOfHeaders: number;
  checkSum: number;
  subsystem: number;
  subsystemName: string;
  dllCharacteristics: number;
  dllCharacteristicsList: string[];
  sizeOfStackReserve: string;
  sizeOfStackCommit: string;
  sizeOfHeapReserve: string;
  sizeOfHeapCommit: string;
  loaderFlags: number;
  numberOfRvaAndSizes: number;
  dataDirectories: DataDirectory[];
}

export interface SectionHeader {
  index: number;
  name: string;
  virtualSize: number;
  virtualAddress: number;
  sizeOfRawData: number;
  pointerToRawData: number;
  pointerToRelocations: number;
  pointerToLinenumbers: number;
  numberOfRelocations: number;
  numberOfLinenumbers: number;
  characteristics: number;
  flagsList: string[];
  permissions: string;
  entropy?: number;
  entropyStatus?: 'low' | 'normal' | 'high';
  headerOffset: number;
}

export interface ImportFunction {
  name: string;
  hint?: number;
  ordinal?: number;
}

export interface ImportedModule {
  name: string;
  timeDateStamp: number;
  forwarderChain: number;
  functions: ImportFunction[];
}

export interface ExportFunction {
  name?: string;
  ordinal: number;
  rva: number;
  forwarder?: string;
  isForwarder: boolean;
}

export interface ExportDirectory {
  characteristics: number;
  timeDateStamp: number;
  timeDateString: string;
  majorVersion: number;
  minorVersion: number;
  nameRva: number;
  dllName: string;
  base: number;
  numberOfFunctions: number;
  numberOfNames: number;
  addressOfFunctions: number;
  addressOfNames: number;
  addressOfNameOrdinals: number;
  functions: ExportFunction[];
  directoryOffset: number;
}

export interface SecurityAnalysis {
  aslr: boolean;
  highEntropyVa: boolean;
  dep: boolean;
  cfg: boolean;
  authenticode: boolean;
  certSize: number;
  noSeh: boolean;
  safeSeh: boolean;
  isDotNet: boolean;
  subsystem: string;
  arch: string;
  overallScore: 'High' | 'Medium' | 'Low';
  notes: string[];
}

export interface ParsedPE {
  isValidPE: boolean;
  errorMessage?: string;
  fileSize: number;
  dosHeader: DosHeader;
  dosStubText?: string;
  richHeader?: RichHeader;
  peSignatureOffset: number;
  fileHeader: FileHeader;
  optionalHeader?: OptionalHeader;
  sections: SectionHeader[];
  exportDirectory?: ExportDirectory;
  imports?: ImportedModule[];
  security: SecurityAnalysis;
  spans: ByteSpan[];
  data: Uint8Array;
}

// Machine Types map
const MACHINE_TYPES: Record<number, string> = {
  0x014c: 'Intel 386 (x86 32-bit)',
  0x8664: 'AMD64 (x86-64 64-bit)',
  0xAA64: 'ARM64 (Little Endian)',
  0x01c0: 'ARM (Little Endian)',
  0x01c4: 'ARM Thumb-2',
  0x0200: 'Intel Itanium (IA-64)',
  0x5032: 'RISC-V 32-bit',
  0x5064: 'RISC-V 64-bit',
  0x5128: 'RISC-V 128-bit',
  0x0EBC: 'EFI Byte Code (EBC)',
  0x01f0: 'PowerPC Little Endian',
  0x0266: 'MIPS16',
  0x0366: 'MIPS with FPU',
};

// Subsystem map
const SUBSYSTEM_TYPES: Record<number, string> = {
  1: 'Native (Device Driver / NT Subsystem)',
  2: 'Windows GUI (Graphical Application)',
  3: 'Windows CUI (Console / Command Line)',
  5: 'OS/2 Console',
  7: 'POSIX Console',
  9: 'Windows CE GUI',
  10: 'EFI Application',
  11: 'EFI Boot Service Driver',
  12: 'EFI Runtime Driver',
  13: 'EFI ROM Image',
  14: 'Xbox',
  16: 'Windows Boot Application',
};

// Data Directory names
const DATA_DIR_NAMES = [
  'Export Table',
  'Import Table',
  'Resource Table',
  'Exception Table (.pdata)',
  'Certificate Table (Authenticode)',
  'Base Relocation Table (.reloc)',
  'Debug Directory',
  'Architecture Specific Data',
  'Global Pointer (RVA)',
  'TLS Table (Thread Local Storage)',
  'Load Config Table',
  'Bound Import Table',
  'Import Address Table (IAT)',
  'Delay Import Descriptor',
  'CLR Runtime Header (.NET)',
  'Reserved',
];

// Rich Header Tool IDs map
const RICH_TOOL_MAP: Record<number, string> = {
  0x0001: 'Utc16_LTCG',
  0x0002: 'Utc16_MP',
  0x0003: 'Utc16_C',
  0x0004: 'Utc16_CPP',
  0x0093: 'CVTRES',
  0x0094: 'Linker',
  0x0095: 'Export',
  0x0096: 'MSASM',
  0x0097: 'C Compiler (C)',
  0x0098: 'C++ Compiler (C++)',
  0x0103: 'VS 2015 C++',
  0x0104: 'VS 2017 C++',
  0x0105: 'VS 2019 C++',
  0x0106: 'VS 2022 C++',
  0x0107: 'VS 2022 Linker',
  0x0108: 'VS 2022 Resource Compiler',
};

function getVsVersion(buildId: number): string {
  if (buildId >= 30000) return 'Visual Studio 2022';
  if (buildId >= 25000) return 'Visual Studio 2019';
  if (buildId >= 20000) return 'Visual Studio 2017';
  if (buildId >= 19000) return 'Visual Studio 2015';
  if (buildId >= 18000) return 'Visual Studio 2013';
  if (buildId >= 17000) return 'Visual Studio 2012';
  if (buildId >= 16000) return 'Visual Studio 2010';
  if (buildId >= 15000) return 'Visual Studio 2008';
  return 'MSVC Build ' + buildId;
}

// Calculate Shannon entropy for a slice of bytes
export function calculateEntropy(bytes: Uint8Array): number {
  if (bytes.length === 0) return 0;
  const frequencies = new Array(256).fill(0);
  for (let i = 0; i < bytes.length; i++) {
    frequencies[bytes[i]]++;
  }
  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    if (frequencies[i] > 0) {
      const p = frequencies[i] / bytes.length;
      entropy -= p * Math.log2(p);
    }
  }
  return Number(entropy.toFixed(3));
}

// Find which section contains a given RVA
export function findSectionByRva(sections: SectionHeader[], rva: number): SectionHeader | undefined {
  return sections.find(
    (s) => rva >= s.virtualAddress && rva < s.virtualAddress + Math.max(s.virtualSize, s.sizeOfRawData)
  );
}

// Convert RVA to File Offset
export function rvaToFileOffset(sections: SectionHeader[], rva: number): number | null {
  const section = findSectionByRva(sections, rva);
  if (!section) return null;
  return rva - section.virtualAddress + section.pointerToRawData;
}

export function parsePE(buffer: ArrayBuffer | Uint8Array): ParsedPE {
  const data = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const spans: ByteSpan[] = [];

  const fail = (msg: string): ParsedPE => ({
    isValidPE: false,
    errorMessage: msg,
    fileSize: data.length,
    dosHeader: {} as DosHeader,
    peSignatureOffset: 0,
    fileHeader: {} as FileHeader,
    sections: [],
    security: {
      aslr: false,
      highEntropyVa: false,
      dep: false,
      cfg: false,
      authenticode: false,
      certSize: 0,
      noSeh: false,
      safeSeh: false,
      isDotNet: false,
      subsystem: 'Unknown',
      arch: 'Unknown',
      overallScore: 'Low',
      notes: [msg],
    },
    spans: [],
    data,
  });

  if (data.length < 64) {
    return fail('File is too small to contain a valid DOS header (minimum 64 bytes).');
  }

  // 1. Parse DOS Header
  const e_magic = view.getUint16(0, true);
  if (e_magic !== 0x5a4d) {
    return fail(`Invalid DOS signature: 0x${e_magic.toString(16).toUpperCase()} (Expected 0x5A4D 'MZ'). This is not a Windows executable.`);
  }

  const dosHeader: DosHeader = {
    e_magic,
    e_cblp: view.getUint16(2, true),
    e_cp: view.getUint16(4, true),
    e_crlc: view.getUint16(6, true),
    e_cparhdr: view.getUint16(8, true),
    e_minalloc: view.getUint16(10, true),
    e_maxalloc: view.getUint16(12, true),
    e_ss: view.getUint16(14, true),
    e_sp: view.getUint16(16, true),
    e_csum: view.getUint16(18, true),
    e_ip: view.getUint16(20, true),
    e_cs: view.getUint16(22, true),
    e_lfarlc: view.getUint16(24, true),
    e_ovno: view.getUint16(26, true),
    e_res: [view.getUint16(28, true), view.getUint16(30, true), view.getUint16(32, true), view.getUint16(34, true)],
    e_oemid: view.getUint16(36, true),
    e_oeminfo: view.getUint16(38, true),
    e_res2: Array.from({ length: 10 }, (_, i) => view.getUint16(40 + i * 2, true)),
    e_lfanew: view.getInt32(60, true),
  };

  spans.push({
    start: 0,
    end: 2,
    name: 'DOS Magic (MZ)',
    category: 'dos',
    description: "Mark Zbikowski signature 'MZ' (0x5A4D)",
    valueStr: '0x5A4D (MZ)',
  });
  spans.push({
    start: 2,
    end: 60,
    name: 'IMAGE_DOS_HEADER Fields',
    category: 'dos',
    description: 'DOS execution registers, relocation tables, and reserved fields',
  });
  spans.push({
    start: 60,
    end: 64,
    name: 'e_lfanew',
    category: 'dos',
    description: `File offset pointing to the PE signature (0x${dosHeader.e_lfanew.toString(16).toUpperCase()})`,
    valueStr: `0x${dosHeader.e_lfanew.toString(16).toUpperCase()} (${dosHeader.e_lfanew} bytes)`,
  });

  const peOffset = dosHeader.e_lfanew;

  if (peOffset <= 0 || peOffset + 4 > data.length) {
    return fail(`e_lfanew offset (0x${peOffset.toString(16)}) points outside the binary range (size: ${data.length} bytes).`);
  }

  // 2. Read DOS Stub Text if present
  let dosStubText: string | undefined;
  if (peOffset > 64) {
    const stubBytes = data.subarray(64, Math.min(peOffset, 256));
    let ascii = '';
    for (let i = 0; i < stubBytes.length; i++) {
      const b = stubBytes[i];
      if (b >= 32 && b <= 126) ascii += String.fromCharCode(b);
      else if (ascii.length > 5 && ascii.includes('DOS')) break;
    }
    if (ascii.length >= 4) {
      dosStubText = ascii.trim();
    }
    spans.push({
      start: 64,
      end: peOffset,
      name: 'DOS Stub Program',
      category: 'dos_stub',
      description: 'Legacy 16-bit DOS real-mode stub program',
      valueStr: dosStubText || '16-bit MS-DOS stub',
    });
  }

  // 3. Scan for MSVC Rich Header
  let richHeader: RichHeader | undefined;
  if (peOffset > 64) {
    for (let i = 64; i < peOffset - 8; i += 4) {
      // Look for "Rich" marker (0x68636952)
      if (view.getUint32(i, true) === 0x68636952) {
        const xorKey = view.getUint32(i + 4, true);
        // Look backwards for "DanS" XOR'd with key (0x536E6144 ^ xorKey)
        const expectedDans = 0x536e6144 ^ xorKey;
        for (let j = i - 4; j >= 64; j -= 4) {
          if (view.getUint32(j, true) === expectedDans) {
            const richStart = j;
            const richEnd = i + 8;
            const entries: RichHeaderEntry[] = [];
            // Parse entries between j + 16 (after DanS + 3 null dwords) and i
            for (let k = j + 16; k < i; k += 8) {
              const compIdRaw = view.getUint32(k, true) ^ xorKey;
              const count = view.getUint32(k + 4, true) ^ xorKey;
              const toolId = (compIdRaw >>> 16) & 0xffff;
              const buildId = compIdRaw & 0xffff;
              const toolName = RICH_TOOL_MAP[toolId] || `Tool 0x${toolId.toString(16).toUpperCase()}`;
              const vsVersion = getVsVersion(buildId);
              entries.push({
                toolId,
                toolName,
                buildId,
                vsVersion,
                count,
              });
            }

            richHeader = {
              offset: richStart,
              size: richEnd - richStart,
              xorKey,
              entries,
            };

            spans.push({
              start: richStart,
              end: richEnd,
              name: 'MSVC Rich Header',
              category: 'rich',
              description: `Undocumented compiler build metadata (${entries.length} tool records)`,
              valueStr: `Key: 0x${xorKey.toString(16).toUpperCase()}, Records: ${entries.length}`,
            });
            break;
          }
        }
        break;
      }
    }
  }

  // 4. Validate PE Signature
  const peSignature = view.getUint32(peOffset, true);
  if (peSignature !== 0x00004550) {
    return fail(`Invalid PE signature at offset 0x${peOffset.toString(16)}: 0x${peSignature.toString(16).toUpperCase()} (Expected 0x00004550 'PE\\0\\0').`);
  }

  spans.push({
    start: peOffset,
    end: peOffset + 4,
    name: 'PE Signature (PE\\0\\0)',
    category: 'nt_sig',
    description: "IMAGE_NT_SIGNATURE 'PE\\0\\0' (0x00004550)",
    valueStr: 'PE\\0\\0',
  });

  // 5. Parse COFF File Header
  const coffOffset = peOffset + 4;
  if (coffOffset + 20 > data.length) {
    return fail('File truncated within COFF IMAGE_FILE_HEADER.');
  }

  const machine = view.getUint16(coffOffset, true);
  const numberOfSections = view.getUint16(coffOffset + 2, true);
  const timeDateStamp = view.getUint32(coffOffset + 4, true);
  const pointerToSymbolTable = view.getUint32(coffOffset + 8, true);
  const numberOfSymbols = view.getUint32(coffOffset + 12, true);
  const sizeOfOptionalHeader = view.getUint16(coffOffset + 16, true);
  const characteristics = view.getUint16(coffOffset + 18, true);

  const characteristicsList: string[] = [];
  if (characteristics & 0x0001) characteristicsList.push('RELOCS_STRIPPED');
  if (characteristics & 0x0002) characteristicsList.push('EXECUTABLE_IMAGE');
  if (characteristics & 0x0004) characteristicsList.push('LINE_NUMS_STRIPPED');
  if (characteristics & 0x0008) characteristicsList.push('LOCAL_SYMS_STRIPPED');
  if (characteristics & 0x0010) characteristicsList.push('AGGRESSIVE_WS_TRIM');
  if (characteristics & 0x0020) characteristicsList.push('LARGE_ADDRESS_AWARE');
  if (characteristics & 0x0080) characteristicsList.push('BYTES_REVERSED_LO');
  if (characteristics & 0x0100) characteristicsList.push('32BIT_MACHINE');
  if (characteristics & 0x0200) characteristicsList.push('DEBUG_STRIPPED');
  if (characteristics & 0x0400) characteristicsList.push('REMOVABLE_RUN_FROM_SWAP');
  if (characteristics & 0x0800) characteristicsList.push('NET_RUN_FROM_SWAP');
  if (characteristics & 0x1000) characteristicsList.push('SYSTEM');
  if (characteristics & 0x2000) characteristicsList.push('DLL');
  if (characteristics & 0x4000) characteristicsList.push('UP_SYSTEM_ONLY');
  if (characteristics & 0x8000) characteristicsList.push('BYTES_REVERSED_HI');

  const fileHeader: FileHeader = {
    machine,
    machineName: MACHINE_TYPES[machine] || `Unknown Machine (0x${machine.toString(16).toUpperCase()})`,
    numberOfSections,
    timeDateStamp,
    timeDateString: new Date(timeDateStamp * 1000).toUTCString(),
    pointerToSymbolTable,
    numberOfSymbols,
    sizeOfOptionalHeader,
    characteristics,
    characteristicsList,
  };

  spans.push({
    start: coffOffset,
    end: coffOffset + 20,
    name: 'IMAGE_FILE_HEADER (COFF)',
    category: 'file_header',
    description: `Target: ${fileHeader.machineName}, ${numberOfSections} sections`,
    valueStr: `${fileHeader.machineName}, Sections: ${numberOfSections}`,
  });

  // 6. Parse Optional Header
  const optOffset = coffOffset + 20;
  let optionalHeader: OptionalHeader | undefined;

  if (sizeOfOptionalHeader > 0 && optOffset + 2 <= data.length) {
    const magic = view.getUint16(optOffset, true);
    const is64Bit = magic === 0x20b; // PE32+
    const is32Bit = magic === 0x10b; // PE32

    if (is64Bit || is32Bit) {
      const majorLinkerVersion = view.getUint8(optOffset + 2);
      const minorLinkerVersion = view.getUint8(optOffset + 3);
      const sizeOfCode = view.getUint32(optOffset + 4, true);
      const sizeOfInitializedData = view.getUint32(optOffset + 8, true);
      const sizeOfUninitializedData = view.getUint32(optOffset + 12, true);
      const addressOfEntryPoint = view.getUint32(optOffset + 16, true);
      const baseOfCode = view.getUint32(optOffset + 20, true);

      let baseOfData: number | undefined;
      let imageBase = '';
      let sectionAlignment = 0;
      let fileAlignment = 0;
      let majorOS = 0, minorOS = 0;
      let majorImg = 0, minorImg = 0;
      let majorSub = 0, minorSub = 0;
      let win32Val = 0;
      let sizeOfImage = 0;
      let sizeOfHeaders = 0;
      let checkSum = 0;
      let subsystem = 0;
      let dllCharacteristics = 0;
      let sizeOfStackReserve = '0';
      let sizeOfStackCommit = '0';
      let sizeOfHeapReserve = '0';
      let sizeOfHeapCommit = '0';
      let loaderFlags = 0;
      let numberOfRvaAndSizes = 0;
      let dataDirOffset = 0;

      if (!is64Bit) {
        // PE32 (32-bit)
        baseOfData = view.getUint32(optOffset + 24, true);
        imageBase = '0x' + view.getUint32(optOffset + 28, true).toString(16).padStart(8, '0').toUpperCase();
        sectionAlignment = view.getUint32(optOffset + 32, true);
        fileAlignment = view.getUint32(optOffset + 36, true);
        majorOS = view.getUint16(optOffset + 40, true);
        minorOS = view.getUint16(optOffset + 42, true);
        majorImg = view.getUint16(optOffset + 44, true);
        minorImg = view.getUint16(optOffset + 46, true);
        majorSub = view.getUint16(optOffset + 48, true);
        minorSub = view.getUint16(optOffset + 50, true);
        win32Val = view.getUint32(optOffset + 52, true);
        sizeOfImage = view.getUint32(optOffset + 56, true);
        sizeOfHeaders = view.getUint32(optOffset + 60, true);
        checkSum = view.getUint32(optOffset + 64, true);
        subsystem = view.getUint16(optOffset + 68, true);
        dllCharacteristics = view.getUint16(optOffset + 70, true);
        sizeOfStackReserve = '0x' + view.getUint32(optOffset + 72, true).toString(16).toUpperCase();
        sizeOfStackCommit = '0x' + view.getUint32(optOffset + 76, true).toString(16).toUpperCase();
        sizeOfHeapReserve = '0x' + view.getUint32(optOffset + 80, true).toString(16).toUpperCase();
        sizeOfHeapCommit = '0x' + view.getUint32(optOffset + 84, true).toString(16).toUpperCase();
        loaderFlags = view.getUint32(optOffset + 88, true);
        numberOfRvaAndSizes = view.getUint32(optOffset + 92, true);
        dataDirOffset = optOffset + 96;
      } else {
        // PE32+ (64-bit)
        const imageBaseLo = view.getUint32(optOffset + 24, true);
        const imageBaseHi = view.getUint32(optOffset + 28, true);
        const imageBaseBig = (BigInt(imageBaseHi) << 32n) | BigInt(imageBaseLo);
        imageBase = '0x' + imageBaseBig.toString(16).padStart(16, '0').toUpperCase();

        sectionAlignment = view.getUint32(optOffset + 32, true);
        fileAlignment = view.getUint32(optOffset + 36, true);
        majorOS = view.getUint16(optOffset + 40, true);
        minorOS = view.getUint16(optOffset + 42, true);
        majorImg = view.getUint16(optOffset + 44, true);
        minorImg = view.getUint16(optOffset + 46, true);
        majorSub = view.getUint16(optOffset + 48, true);
        minorSub = view.getUint16(optOffset + 50, true);
        win32Val = view.getUint32(optOffset + 52, true);
        sizeOfImage = view.getUint32(optOffset + 56, true);
        sizeOfHeaders = view.getUint32(optOffset + 60, true);
        checkSum = view.getUint32(optOffset + 64, true);
        subsystem = view.getUint16(optOffset + 68, true);
        dllCharacteristics = view.getUint16(optOffset + 70, true);

        const stackResLo = view.getUint32(optOffset + 72, true);
        const stackResHi = view.getUint32(optOffset + 76, true);
        sizeOfStackReserve = '0x' + ((BigInt(stackResHi) << 32n) | BigInt(stackResLo)).toString(16).toUpperCase();

        const stackComLo = view.getUint32(optOffset + 80, true);
        const stackComHi = view.getUint32(optOffset + 84, true);
        sizeOfStackCommit = '0x' + ((BigInt(stackComHi) << 32n) | BigInt(stackComLo)).toString(16).toUpperCase();

        const heapResLo = view.getUint32(optOffset + 88, true);
        const heapResHi = view.getUint32(optOffset + 92, true);
        sizeOfHeapReserve = '0x' + ((BigInt(heapResHi) << 32n) | BigInt(heapResLo)).toString(16).toUpperCase();

        const heapComLo = view.getUint32(optOffset + 96, true);
        const heapComHi = view.getUint32(optOffset + 100, true);
        sizeOfHeapCommit = '0x' + ((BigInt(heapComHi) << 32n) | BigInt(heapComLo)).toString(16).toUpperCase();

        loaderFlags = view.getUint32(optOffset + 104, true);
        numberOfRvaAndSizes = view.getUint32(optOffset + 108, true);
        dataDirOffset = optOffset + 112;
      }

      const dllCharacteristicsList: string[] = [];
      if (dllCharacteristics & 0x0020) dllCharacteristicsList.push('HIGH_ENTROPY_VA');
      if (dllCharacteristics & 0x0040) dllCharacteristicsList.push('DYNAMIC_BASE (ASLR)');
      if (dllCharacteristics & 0x0080) dllCharacteristicsList.push('FORCE_INTEGRITY');
      if (dllCharacteristics & 0x0100) dllCharacteristicsList.push('NX_COMPAT (DEP)');
      if (dllCharacteristics & 0x0200) dllCharacteristicsList.push('NO_ISOLATION');
      if (dllCharacteristics & 0x0400) dllCharacteristicsList.push('NO_SEH');
      if (dllCharacteristics & 0x0800) dllCharacteristicsList.push('NO_BIND');
      if (dllCharacteristics & 0x1000) dllCharacteristicsList.push('APPCONTAINER');
      if (dllCharacteristics & 0x2000) dllCharacteristicsList.push('WDM_DRIVER');
      if (dllCharacteristics & 0x4000) dllCharacteristicsList.push('GUARD_CF (Control Flow Guard)');
      if (dllCharacteristics & 0x8000) dllCharacteristicsList.push('TERMINAL_SERVER_AWARE');

      // Parse Data Directories (up to 16)
      const dataDirectories: DataDirectory[] = [];
      const dirCount = Math.min(numberOfRvaAndSizes, 16);
      for (let i = 0; i < dirCount; i++) {
        const entryOffset = dataDirOffset + i * 8;
        if (entryOffset + 8 <= data.length) {
          const va = view.getUint32(entryOffset, true);
          const sz = view.getUint32(entryOffset + 4, true);
          dataDirectories.push({
            index: i,
            name: DATA_DIR_NAMES[i] || `Directory ${i}`,
            virtualAddress: va,
            size: sz,
          });
        }
      }

      optionalHeader = {
        magic,
        is64Bit,
        majorLinkerVersion,
        minorLinkerVersion,
        sizeOfCode,
        sizeOfInitializedData,
        sizeOfUninitializedData,
        addressOfEntryPoint,
        baseOfCode,
        baseOfData,
        imageBase,
        sectionAlignment,
        fileAlignment,
        majorOperatingSystemVersion: majorOS,
        minorOperatingSystemVersion: minorOS,
        majorImageVersion: majorImg,
        minorImageVersion: minorImg,
        majorSubsystemVersion: majorSub,
        minorSubsystemVersion: minorSub,
        win32VersionValue: win32Val,
        sizeOfImage,
        sizeOfHeaders,
        checkSum,
        subsystem,
        subsystemName: SUBSYSTEM_TYPES[subsystem] || `Subsystem 0x${subsystem.toString(16)}`,
        dllCharacteristics,
        dllCharacteristicsList,
        sizeOfStackReserve,
        sizeOfStackCommit,
        sizeOfHeapReserve,
        sizeOfHeapCommit,
        loaderFlags,
        numberOfRvaAndSizes,
        dataDirectories,
      };

      spans.push({
        start: optOffset,
        end: optOffset + (is64Bit ? 112 : 96),
        name: `IMAGE_OPTIONAL_HEADER (${is64Bit ? 'PE32+ 64-bit' : 'PE32 32-bit'})`,
        category: 'optional_header',
        description: `Entry point: 0x${addressOfEntryPoint.toString(16).toUpperCase()}, ImageBase: ${imageBase}`,
        valueStr: `${is64Bit ? 'PE32+' : 'PE32'}, Subsystem: ${optionalHeader.subsystemName}`,
      });

      if (dataDirectories.length > 0) {
        spans.push({
          start: dataDirOffset,
          end: dataDirOffset + dataDirectories.length * 8,
          name: `IMAGE_DATA_DIRECTORY[${dataDirectories.length}]`,
          category: 'data_dirs',
          description: 'Export, Import, Resource, Exception, Certificate and Relocation directories',
        });
      }
    }
  }

  // 7. Parse Section Headers
  const sectionsOffset = optOffset + sizeOfOptionalHeader;
  const sections: SectionHeader[] = [];

  for (let i = 0; i < numberOfSections; i++) {
    const secOffset = sectionsOffset + i * 40;
    if (secOffset + 40 > data.length) break;

    // Read 8-byte ASCII name
    let secName = '';
    for (let j = 0; j < 8; j++) {
      const b = data[secOffset + j];
      if (b === 0) break;
      secName += String.fromCharCode(b);
    }
    secName = secName.trim() || `sec_${i}`;

    const virtualSize = view.getUint32(secOffset + 8, true);
    const virtualAddress = view.getUint32(secOffset + 12, true);
    const sizeOfRawData = view.getUint32(secOffset + 16, true);
    const pointerToRawData = view.getUint32(secOffset + 20, true);
    const pointerToRelocations = view.getUint32(secOffset + 24, true);
    const pointerToLinenumbers = view.getUint32(secOffset + 28, true);
    const numberOfRelocations = view.getUint16(secOffset + 32, true);
    const numberOfLinenumbers = view.getUint16(secOffset + 34, true);
    const characteristics = view.getUint32(secOffset + 36, true);

    const flagsList: string[] = [];
    if (characteristics & 0x00000020) flagsList.push('CNT_CODE');
    if (characteristics & 0x00000040) flagsList.push('CNT_INITIALIZED_DATA');
    if (characteristics & 0x00000080) flagsList.push('CNT_UNINITIALIZED_DATA');
    if (characteristics & 0x02000000) flagsList.push('MEM_DISCARDABLE');
    if (characteristics & 0x04000000) flagsList.push('MEM_NOT_CACHED');
    if (characteristics & 0x08000000) flagsList.push('MEM_NOT_PAGED');
    if (characteristics & 0x10000000) flagsList.push('MEM_SHARED');
    if (characteristics & 0x20000000) flagsList.push('MEM_EXECUTE');
    if (characteristics & 0x40000000) flagsList.push('MEM_READ');
    if (characteristics & 0x80000000) flagsList.push('MEM_WRITE');

    const isRead = (characteristics & 0x40000000) !== 0;
    const isWrite = (characteristics & 0x80000000) !== 0;
    const isExec = (characteristics & 0x20000000) !== 0;
    const permissions = `${isRead ? 'R' : '-'}${isWrite ? 'W' : '-'}${isExec ? 'X' : '-'}`;

    // Calculate entropy if section data exists in downloaded buffer
    let entropy: number | undefined;
    let entropyStatus: 'low' | 'normal' | 'high' | undefined;
    if (pointerToRawData > 0 && pointerToRawData < data.length) {
      const availableBytes = Math.min(sizeOfRawData, data.length - pointerToRawData);
      if (availableBytes > 32) {
        const secBytes = data.subarray(pointerToRawData, pointerToRawData + availableBytes);
        entropy = calculateEntropy(secBytes);
        if (entropy > 7.1) entropyStatus = 'high'; // Packed / encrypted / compressed
        else if (entropy < 1.5) entropyStatus = 'low';
        else entropyStatus = 'normal';
      }
    }

    sections.push({
      index: i,
      name: secName,
      virtualSize,
      virtualAddress,
      sizeOfRawData,
      pointerToRawData,
      pointerToRelocations,
      pointerToLinenumbers,
      numberOfRelocations,
      numberOfLinenumbers,
      characteristics,
      flagsList,
      permissions,
      entropy,
      entropyStatus,
      headerOffset: secOffset,
    });

    spans.push({
      start: secOffset,
      end: secOffset + 40,
      name: `Section Header: ${secName}`,
      category: 'section_headers',
      description: `RVA: 0x${virtualAddress.toString(16).toUpperCase()}, Raw Size: ${sizeOfRawData} bytes, Perms: ${permissions}`,
      valueStr: `${secName} (${permissions})`,
    });
  }

  // Correlate Data Directories with their containing sections
  if (optionalHeader) {
    for (const dir of optionalHeader.dataDirectories) {
      if (dir.virtualAddress > 0) {
        if (dir.index === 4) {
          // Certificate table VA is a FILE OFFSET, not an RVA!
          dir.sectionName = 'Raw File Offset';
        } else {
          const matchSec = findSectionByRva(sections, dir.virtualAddress);
          if (matchSec) dir.sectionName = matchSec.name;
        }
      }
    }
  }

  // 8. Parse Export Directory if present (IMAGE_DIRECTORY_ENTRY_EXPORT = 0)
  let exportDirectory: ExportDirectory | undefined;
  if (optionalHeader && optionalHeader.dataDirectories[0]) {
    const exportDirEntry = optionalHeader.dataDirectories[0];
    if (exportDirEntry.virtualAddress > 0 && exportDirEntry.size > 0) {
      const exportOffset = rvaToFileOffset(sections, exportDirEntry.virtualAddress);
      if (exportOffset !== null && exportOffset + 40 <= data.length) {
        const characteristics = view.getUint32(exportOffset, true);
        const timeDateStamp = view.getUint32(exportOffset + 4, true);
        const majorVersion = view.getUint16(exportOffset + 8, true);
        const minorVersion = view.getUint16(exportOffset + 10, true);
        const nameRva = view.getUint32(exportOffset + 12, true);
        const base = view.getUint32(exportOffset + 16, true);
        const numberOfFunctions = view.getUint32(exportOffset + 20, true);
        const numberOfNames = view.getUint32(exportOffset + 24, true);
        const addressOfFunctions = view.getUint32(exportOffset + 28, true);
        const addressOfNames = view.getUint32(exportOffset + 32, true);
        const addressOfNameOrdinals = view.getUint32(exportOffset + 36, true);

        let dllName = '';
        const nameOffset = rvaToFileOffset(sections, nameRva);
        if (nameOffset !== null && nameOffset < data.length) {
          for (let k = nameOffset; k < Math.min(nameOffset + 256, data.length); k++) {
            if (data[k] === 0) break;
            dllName += String.fromCharCode(data[k]);
          }
        }

        const functions: ExportFunction[] = [];
        const usedOrdinalIndices = new Set<number>();

        const maxExportCount = 4096;
        const safeNumberOfNames = Math.min(numberOfNames, maxExportCount);
        const safeNumberOfFunctions = Math.min(numberOfFunctions, maxExportCount);

        const eatOffset = rvaToFileOffset(sections, addressOfFunctions);
        const nptOffset = rvaToFileOffset(sections, addressOfNames);
        const otOffset = rvaToFileOffset(sections, addressOfNameOrdinals);

        // Parse named exports
        if (nptOffset !== null && otOffset !== null && eatOffset !== null) {
          for (let i = 0; i < safeNumberOfNames; i++) {
            const nameEntryOffset = nptOffset + i * 4;
            const ordinalEntryOffset = otOffset + i * 2;
            if (nameEntryOffset + 4 > data.length || ordinalEntryOffset + 2 > data.length) break;

            const fnNameRva = view.getUint32(nameEntryOffset, true);
            const ordinalIndex = view.getUint16(ordinalEntryOffset, true);
            usedOrdinalIndices.add(ordinalIndex);

            let fnName = '';
            const fnNameOffset = rvaToFileOffset(sections, fnNameRva);
            if (fnNameOffset !== null && fnNameOffset < data.length) {
              for (let k = fnNameOffset; k < Math.min(fnNameOffset + 256, data.length); k++) {
                if (data[k] === 0) break;
                fnName += String.fromCharCode(data[k]);
              }
            }

            let funcRva = 0;
            const eatEntryOffset = eatOffset + ordinalIndex * 4;
            if (eatEntryOffset + 4 <= data.length) {
              funcRva = view.getUint32(eatEntryOffset, true);
            }

            const ordinal = base + ordinalIndex;
            let forwarder: string | undefined;
            const isForwarder =
              funcRva >= exportDirEntry.virtualAddress &&
              funcRva < exportDirEntry.virtualAddress + exportDirEntry.size;

            if (isForwarder) {
              const forwarderOffset = rvaToFileOffset(sections, funcRva);
              if (forwarderOffset !== null && forwarderOffset < data.length) {
                let fwdStr = '';
                for (let k = forwarderOffset; k < Math.min(forwarderOffset + 256, data.length); k++) {
                  if (data[k] === 0) break;
                  fwdStr += String.fromCharCode(data[k]);
                }
                forwarder = fwdStr;
              }
            }

            functions.push({
              name: fnName || `export_rva_${funcRva.toString(16).toUpperCase()}`,
              ordinal,
              rva: funcRva,
              forwarder,
              isForwarder,
            });
          }

          // Parse ordinal-only exports in EAT
          for (let j = 0; j < safeNumberOfFunctions; j++) {
            if (!usedOrdinalIndices.has(j)) {
              const eatEntryOffset = eatOffset + j * 4;
              if (eatEntryOffset + 4 > data.length) break;
              const funcRva = view.getUint32(eatEntryOffset, true);
              if (funcRva !== 0) {
                const ordinal = base + j;
                const isForwarder =
                  funcRva >= exportDirEntry.virtualAddress &&
                  funcRva < exportDirEntry.virtualAddress + exportDirEntry.size;

                let forwarder: string | undefined;
                if (isForwarder) {
                  const forwarderOffset = rvaToFileOffset(sections, funcRva);
                  if (forwarderOffset !== null && forwarderOffset < data.length) {
                    let fwdStr = '';
                    for (let k = forwarderOffset; k < Math.min(forwarderOffset + 256, data.length); k++) {
                      if (data[k] === 0) break;
                      fwdStr += String.fromCharCode(data[k]);
                    }
                    forwarder = fwdStr;
                  }
                }

                functions.push({
                  name: undefined,
                  ordinal,
                  rva: funcRva,
                  forwarder,
                  isForwarder,
                });
              }
            }
          }
        }

        // Sort by ordinal
        functions.sort((a, b) => a.ordinal - b.ordinal);

        exportDirectory = {
          characteristics,
          timeDateStamp,
          timeDateString: new Date(timeDateStamp * 1000).toUTCString(),
          majorVersion,
          minorVersion,
          nameRva,
          dllName: dllName || 'Unknown DLL',
          base,
          numberOfFunctions,
          numberOfNames,
          addressOfFunctions,
          addressOfNames,
          addressOfNameOrdinals,
          functions,
          directoryOffset: exportOffset,
        };

        spans.push({
          start: exportOffset,
          end: exportOffset + 40,
          name: `IMAGE_EXPORT_DIRECTORY: ${dllName || 'Export Directory'}`,
          category: 'export_dir',
          description: `DLL: ${dllName || 'Export Table'}, ${functions.length} exported functions (Ordinal Base: ${base})`,
          valueStr: `${dllName || 'DLL Exports'} (${functions.length} funcs)`,
        });
      }
    }
  }

  // 9. Parse Imports if Import Table is within the downloaded buffer
  const imports: ImportedModule[] = [];
  if (optionalHeader && optionalHeader.dataDirectories[1]) {
    const importDir = optionalHeader.dataDirectories[1];
    if (importDir.virtualAddress > 0 && importDir.size > 0) {
      const fileOffset = rvaToFileOffset(sections, importDir.virtualAddress);
      if (fileOffset !== null && fileOffset < data.length) {
        let curDesc = fileOffset;
        while (curDesc + 20 <= data.length) {
          const origFirstThunk = view.getUint32(curDesc, true);
          const timeDate = view.getUint32(curDesc + 4, true);
          const forwarder = view.getUint32(curDesc + 8, true);
          const nameRva = view.getUint32(curDesc + 12, true);
          const firstThunk = view.getUint32(curDesc + 16, true);

          // Null descriptor terminates the array
          if (origFirstThunk === 0 && nameRva === 0 && firstThunk === 0) break;

          let dllName = '';
          const nameOffset = rvaToFileOffset(sections, nameRva);
          if (nameOffset !== null && nameOffset < data.length) {
            for (let k = nameOffset; k < Math.min(nameOffset + 128, data.length); k++) {
              if (data[k] === 0) break;
              dllName += String.fromCharCode(data[k]);
            }
          }

          if (dllName) {
            const functions: ImportFunction[] = [];
            // Parse some import names from thunk table if within buffer
            const thunkRva = origFirstThunk || firstThunk;
            const thunkOffset = rvaToFileOffset(sections, thunkRva);
            if (thunkOffset !== null && thunkOffset < data.length) {
              const ptrSize = optionalHeader.is64Bit ? 8 : 4;
              const maxFnCount = 15; // sample up to 15 functions per DLL to keep UI snappy
              for (let f = 0; f < maxFnCount; f++) {
                const entry = thunkOffset + f * ptrSize;
                if (entry + ptrSize > data.length) break;

                let val = 0n;
                if (optionalHeader.is64Bit) {
                  const lo = view.getUint32(entry, true);
                  const hi = view.getUint32(entry + 4, true);
                  val = (BigInt(hi) << 32n) | BigInt(lo);
                } else {
                  val = BigInt(view.getUint32(entry, true));
                }

                if (val === 0n) break;

                const isOrdinal = optionalHeader.is64Bit ? (val & 0x8000000000000000n) !== 0n : (val & 0x80000000n) !== 0n;
                if (isOrdinal) {
                  const ord = Number(val & 0xffffn);
                  functions.push({ name: `Ordinal #${ord}`, ordinal: ord });
                } else {
                  const hintNameRva = Number(val & 0x7fffffffn);
                  const hintOffset = rvaToFileOffset(sections, hintNameRva);
                  if (hintOffset !== null && hintOffset + 2 < data.length) {
                    const hint = view.getUint16(hintOffset, true);
                    let fnName = '';
                    for (let c = hintOffset + 2; c < Math.min(hintOffset + 96, data.length); c++) {
                      if (data[c] === 0) break;
                      fnName += String.fromCharCode(data[c]);
                    }
                    if (fnName) {
                      functions.push({ name: fnName, hint });
                    }
                  }
                }
              }
            }

            imports.push({
              name: dllName,
              timeDateStamp: timeDate,
              forwarderChain: forwarder,
              functions,
            });
          }

          curDesc += 20;
          if (imports.length >= 64) break; // sanity limit
        }
      }
    }
  }

  // 9. Evaluate Security Mitigations
  const opt = optionalHeader;
  const aslr = !!(opt && (opt.dllCharacteristics & 0x0040));
  const highEntropyVa = !!(opt && (opt.dllCharacteristics & 0x0020));
  const dep = !!(opt && (opt.dllCharacteristics & 0x0100));
  const cfg = !!(opt && (opt.dllCharacteristics & 0x4000));
  const certDir = opt?.dataDirectories[4];
  const authenticode = !!(certDir && certDir.size > 0);
  const certSize = certDir?.size || 0;
  const noSeh = !!(opt && (opt.dllCharacteristics & 0x0400));
  const safeSeh = !opt?.is64Bit && !noSeh;
  const clrDir = opt?.dataDirectories[14];
  const isDotNet = !!(clrDir && clrDir.virtualAddress > 0 && clrDir.size > 0);

  const notes: string[] = [];
  if (aslr) notes.push('ASLR is enabled (DYNAMIC_BASE).');
  else notes.push('ASLR disabled: vulnerable to fixed-address memory corruption.');

  if (highEntropyVa) notes.push('64-bit High-Entropy ASLR active.');
  if (dep) notes.push('DEP/NX enabled: non-executable stack and heap.');
  else notes.push('DEP/NX disabled: executable stack/heap allowed.');

  if (cfg) notes.push('Control Flow Guard (CFG) active: indirect calls protected.');
  if (authenticode) notes.push(`Digitally signed (Authenticode cert size: ${(certSize / 1024).toFixed(1)} KB).`);
  else notes.push('Not digitally signed (no embedded Authenticode certificate).');

  if (isDotNet) notes.push('.NET Managed Executable (contains CLR Runtime Header).');

  let scorePoints = 0;
  if (aslr) scorePoints += 25;
  if (dep) scorePoints += 25;
  if (cfg) scorePoints += 20;
  if (authenticode) scorePoints += 20;
  if (highEntropyVa) scorePoints += 10;

  const overallScore: 'High' | 'Medium' | 'Low' = scorePoints >= 70 ? 'High' : scorePoints >= 40 ? 'Medium' : 'Low';

  const security: SecurityAnalysis = {
    aslr,
    highEntropyVa,
    dep,
    cfg,
    authenticode,
    certSize,
    noSeh,
    safeSeh,
    isDotNet,
    subsystem: opt?.subsystemName || 'Unknown',
    arch: fileHeader.machineName,
    overallScore,
    notes,
  };

  return {
    isValidPE: true,
    fileSize: data.length,
    dosHeader,
    dosStubText,
    richHeader,
    peSignatureOffset: peOffset,
    fileHeader,
    optionalHeader,
    sections,
    exportDirectory,
    imports,
    security,
    spans,
    data,
  };
}
