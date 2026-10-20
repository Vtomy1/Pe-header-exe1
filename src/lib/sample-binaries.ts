/**
 * Sample Windows Executables & Pre-configured URLs for PE inspection
 */

export interface SamplePE {
  id: string;
  name: string;
  arch: string;
  subsystem: string;
  description: string;
  category: 'Modern x64' | 'Legacy x86' | 'CLI Tool' | 'URL';
  url?: string;
  base64Data?: string;
}

// Minimal authentic x64 PE executable header (DOS Header, DOS Stub, PE Sig, File Header x64, Optional Header PE32+, .text, .rdata, .data sections)
// Generated according to Microsoft PE/COFF specs
function createMinimalX64PE(): Uint8Array {
  const buf = new Uint8Array(1024);
  const view = new DataView(buf.buffer);

  // 1. DOS Header
  view.setUint16(0, 0x5a4d, true); // 'MZ'
  view.setUint16(2, 0x0090, true);
  view.setUint16(4, 0x0003, true);
  view.setUint16(60, 0x0080, true); // e_lfanew = 0x80

  // DOS Stub text
  const stub = 'This program cannot be run in DOS mode.\r\r\n$';
  for (let i = 0; i < stub.length; i++) {
    buf[0x40 + i] = stub.charCodeAt(i);
  }

  // 2. PE Signature at 0x80
  view.setUint32(0x80, 0x00004550, true); // 'PE\0\0'

  // 3. COFF File Header at 0x84 (20 bytes)
  view.setUint16(0x84, 0x8664, true); // IMAGE_FILE_MACHINE_AMD64 (x64)
  view.setUint16(0x86, 3, true);      // 3 sections
  view.setUint32(0x88, 1713500000, true); // TimeDateStamp
  view.setUint32(0x8c, 0, true);      // PointerToSymbolTable
  view.setUint32(0x90, 0, true);      // NumberOfSymbols
  view.setUint16(0x94, 240, true);    // SizeOfOptionalHeader (240 for PE32+)
  view.setUint16(0x96, 0x0022, true); // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

  // 4. Optional Header PE32+ at 0x98 (240 bytes)
  view.setUint16(0x98, 0x020b, true); // PE32+ Magic
  view.setUint8(0x9a, 14);            // MajorLinkerVersion (MSVC 14.x)
  view.setUint8(0x9b, 34);            // MinorLinkerVersion
  view.setUint32(0x9c, 0x1000, true); // SizeOfCode
  view.setUint32(0xa0, 0x0800, true); // SizeOfInitializedData
  view.setUint32(0xa4, 0x0000, true); // SizeOfUninitializedData
  view.setUint32(0xa8, 0x1000, true); // AddressOfEntryPoint (RVA)
  view.setUint32(0xac, 0x1000, true); // BaseOfCode
  // ImageBase (64-bit): 0x0000000140000000
  view.setUint32(0xb0, 0x40000000, true);
  view.setUint32(0xb4, 0x00000001, true);
  view.setUint32(0xb8, 0x1000, true); // SectionAlignment (4096)
  view.setUint32(0xbc, 0x0200, true); // FileAlignment (512)
  view.setUint16(0xc0, 6, true);      // MajorOSVersion (Win10)
  view.setUint16(0xc2, 0, true);      // MinorOSVersion
  view.setUint16(0xc8, 6, true);      // MajorSubsystemVersion
  view.setUint16(0xca, 0, true);      // MinorSubsystemVersion
  view.setUint32(0xd0, 0x4000, true); // SizeOfImage
  view.setUint32(0xd4, 0x0400, true); // SizeOfHeaders
  view.setUint32(0xd8, 0x0000, true); // CheckSum
  view.setUint16(0xdc, 2, true);      // Subsystem: IMAGE_SUBSYSTEM_WINDOWS_GUI
  // DllCharacteristics: HIGH_ENTROPY_VA (0x20) | DYNAMIC_BASE (0x40) | NX_COMPAT (0x100) | GUARD_CF (0x4000) | TERMINAL_SERVER (0x8000)
  view.setUint16(0xde, 0xc160, true);
  // Stack reserve / commit
  view.setUint32(0xe0, 0x100000, true);
  view.setUint32(0xe8, 0x1000, true);
  // Heap reserve / commit
  view.setUint32(0xf0, 0x100000, true);
  view.setUint32(0xf8, 0x1000, true);
  view.setUint32(0x104, 16, true);    // NumberOfRvaAndSizes

  // Data directories (16 entries * 8 bytes = 128 bytes, starting at 0x108)
  // Entry 1: Import Table at RVA 0x2000, Size 0x50
  view.setUint32(0x108 + 1 * 8, 0x2000, true);
  view.setUint32(0x108 + 1 * 8 + 4, 0x0050, true);
  // Entry 4: Certificate / Authenticode Table at File Offset 0x0380, Size 0x0400
  view.setUint32(0x108 + 4 * 8, 0x0380, true);
  view.setUint32(0x108 + 4 * 8 + 4, 0x0400, true);

  // 5. Section Headers starting at 0x188
  // Section 1: .text (Code)
  const secText = '.text\0\0\0';
  for (let i = 0; i < 8; i++) buf[0x188 + i] = secText.charCodeAt(i);
  view.setUint32(0x188 + 8, 0x0d20, true);  // VirtualSize
  view.setUint32(0x188 + 12, 0x1000, true); // VirtualAddress
  view.setUint32(0x188 + 16, 0x0e00, true); // SizeOfRawData
  view.setUint32(0x188 + 20, 0x0400, true); // PointerToRawData
  view.setUint32(0x188 + 36, 0x60000020, true); // CNT_CODE | MEM_EXECUTE | MEM_READ

  // Section 2: .rdata (Read-only data, imports)
  const secRdata = '.rdata\0\0';
  for (let i = 0; i < 8; i++) buf[0x1b0 + i] = secRdata.charCodeAt(i);
  view.setUint32(0x1b0 + 8, 0x0600, true);  // VirtualSize
  view.setUint32(0x1b0 + 12, 0x2000, true); // VirtualAddress
  view.setUint32(0x1b0 + 16, 0x0600, true); // SizeOfRawData
  view.setUint32(0x1b0 + 20, 0x1200, true); // PointerToRawData
  view.setUint32(0x1b0 + 36, 0x40000040, true); // CNT_INITIALIZED_DATA | MEM_READ

  // Section 3: .data (Read/Write data)
  const secData = '.data\0\0\0';
  for (let i = 0; i < 8; i++) buf[0x1d8 + i] = secData.charCodeAt(i);
  view.setUint32(0x1d8 + 8, 0x0400, true);  // VirtualSize
  view.setUint32(0x1d8 + 12, 0x3000, true); // VirtualAddress
  view.setUint32(0x1d8 + 16, 0x0200, true); // SizeOfRawData
  view.setUint32(0x1d8 + 20, 0x1800, true); // PointerToRawData
  view.setUint32(0x1d8 + 36, 0xc0000040, true); // CNT_INITIALIZED_DATA | MEM_READ | MEM_WRITE

  return buf;
}

function createSampleDllWithExports(): Uint8Array {
  const buf = new Uint8Array(2048);
  const view = new DataView(buf.buffer);

  // 1. DOS Header
  view.setUint16(0, 0x5a4d, true); // 'MZ'
  view.setUint16(2, 0x0090, true);
  view.setUint16(60, 0x0080, true); // e_lfanew = 0x80

  const stub = 'This program cannot be run in DOS mode.\r\r\n$';
  for (let i = 0; i < stub.length; i++) {
    buf[0x40 + i] = stub.charCodeAt(i);
  }

  // 2. PE Signature at 0x80
  view.setUint32(0x80, 0x00004550, true); // 'PE\0\0'

  // 3. COFF File Header at 0x84
  view.setUint16(0x84, 0x8664, true); // AMD64
  view.setUint16(0x86, 2, true);      // 2 sections (.text, .rdata)
  view.setUint32(0x88, 1713500000, true);
  view.setUint16(0x94, 240, true);    // SizeOfOptionalHeader
  view.setUint16(0x96, 0x2022, true); // DLL | EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

  // 4. Optional Header PE32+ at 0x98
  view.setUint16(0x98, 0x020b, true); // PE32+
  view.setUint8(0x9a, 14);            // MajorLinkerVersion
  view.setUint8(0x9b, 34);            // MinorLinkerVersion
  view.setUint32(0x9c, 0x0400, true); // SizeOfCode
  view.setUint32(0xa0, 0x0600, true); // SizeOfInitializedData
  view.setUint32(0xa8, 0x1000, true); // AddressOfEntryPoint
  view.setUint32(0xac, 0x1000, true); // BaseOfCode
  // ImageBase (64-bit DLL): 0x0000000180000000
  view.setUint32(0xb0, 0x80000000, true);
  view.setUint32(0xb4, 0x00000001, true);
  view.setUint32(0xb8, 0x1000, true); // SectionAlignment
  view.setUint32(0xbc, 0x0200, true); // FileAlignment
  view.setUint16(0xc0, 6, true);
  view.setUint16(0xc8, 6, true);
  view.setUint32(0xd0, 0x3000, true); // SizeOfImage
  view.setUint32(0xd4, 0x0400, true); // SizeOfHeaders
  view.setUint16(0xdc, 2, true);      // Subsystem: Windows GUI
  view.setUint16(0xde, 0x4160, true); // DllCharacteristics: DYNAMIC_BASE | NX_COMPAT | HIGH_ENTROPY_VA | GUARD_CF
  view.setUint32(0x104, 16, true);    // NumberOfRvaAndSizes

  // Data Directory 0 (Export Table): RVA 0x2000, Size 0x0180
  view.setUint32(0x108, 0x2000, true);
  view.setUint32(0x10c, 0x0180, true);

  // 5. Section Headers at 0x188
  // Section 1: .text at 0x188
  const secText = '.text\0\0\0';
  for (let i = 0; i < 8; i++) buf[0x188 + i] = secText.charCodeAt(i);
  view.setUint32(0x188 + 8, 0x0400, true);  // VirtualSize
  view.setUint32(0x188 + 12, 0x1000, true); // VirtualAddress
  view.setUint32(0x188 + 16, 0x0200, true); // SizeOfRawData
  view.setUint32(0x188 + 20, 0x0400, true); // PointerToRawData
  view.setUint32(0x188 + 36, 0x60000020, true); // CNT_CODE | MEM_EXECUTE | MEM_READ

  // Section 2: .rdata at 0x1b0
  const secRdata = '.rdata\0\0';
  for (let i = 0; i < 8; i++) buf[0x1b0 + i] = secRdata.charCodeAt(i);
  view.setUint32(0x1b0 + 8, 0x0600, true);  // VirtualSize
  view.setUint32(0x1b0 + 12, 0x2000, true); // VirtualAddress
  view.setUint32(0x1b0 + 16, 0x0400, true); // SizeOfRawData
  view.setUint32(0x1b0 + 20, 0x0600, true); // PointerToRawData
  view.setUint32(0x1b0 + 36, 0x40000040, true); // CNT_INITIALIZED_DATA | MEM_READ

  // 6. IMAGE_EXPORT_DIRECTORY in .rdata (raw offset 0x0600 = RVA 0x2000)
  view.setUint32(0x0600, 0, true);          // Characteristics
  view.setUint32(0x0604, 1713500000, true); // TimeDateStamp
  view.setUint16(0x0608, 1, true);          // MajorVersion
  view.setUint16(0x060a, 0, true);          // MinorVersion
  view.setUint32(0x060c, 0x2028, true);     // Name RVA -> 0x2028 (offset 0x628)
  view.setUint32(0x0610, 1, true);          // Base = 1
  view.setUint32(0x0614, 4, true);          // NumberOfFunctions = 4
  view.setUint32(0x0618, 3, true);          // NumberOfNames = 3
  view.setUint32(0x061c, 0x2040, true);     // AddressOfFunctions (EAT) -> RVA 0x2040 (offset 0x640)
  view.setUint32(0x0620, 0x2050, true);     // AddressOfNames (ENPT) -> RVA 0x2050 (offset 0x650)
  view.setUint32(0x0624, 0x2060, true);     // AddressOfNameOrdinals (OT) -> RVA 0x2060 (offset 0x660)

  // Write DLL Name string at 0x628
  const dllName = 'CryptoPlugin.dll\0';
  for (let i = 0; i < dllName.length; i++) buf[0x628 + i] = dllName.charCodeAt(i);

  // EAT at offset 0x640 (4 RVAs):
  view.setUint32(0x640, 0x1020, true); // Ordinal 1: InitializePlugin
  view.setUint32(0x644, 0x1050, true); // Ordinal 2: ComputeSHA256
  view.setUint32(0x648, 0x1080, true); // Ordinal 3: GetPluginVersion
  view.setUint32(0x64c, 0x10a0, true); // Ordinal 4: [Ordinal Only]

  // ENPT at offset 0x650 (3 Name RVAs - lexically sorted):
  view.setUint32(0x650, 0x2070, true); // "ComputeSHA256" at 0x670
  view.setUint32(0x654, 0x2088, true); // "GetPluginVersion" at 0x688
  view.setUint32(0x658, 0x20a0, true); // "InitializePlugin" at 0x6A0

  // OT at offset 0x660 (3 Ordinal indices):
  view.setUint16(0x660, 1, true); // ComputeSHA256 -> EAT index 1 (Ordinal 2)
  view.setUint16(0x662, 2, true); // GetPluginVersion -> EAT index 2 (Ordinal 3)
  view.setUint16(0x664, 0, true); // InitializePlugin -> EAT index 0 (Ordinal 1)

  // Write Name Strings:
  const fn1 = 'ComputeSHA256\0';
  for (let i = 0; i < fn1.length; i++) buf[0x670 + i] = fn1.charCodeAt(i);
  const fn2 = 'GetPluginVersion\0';
  for (let i = 0; i < fn2.length; i++) buf[0x688 + i] = fn2.charCodeAt(i);
  const fn3 = 'InitializePlugin\0';
  for (let i = 0; i < fn3.length; i++) buf[0x6a0 + i] = fn3.charCodeAt(i);

  return buf;
}

function bufferToBase64(uint8: Uint8Array): string {
  let binary = '';
  const len = uint8.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(uint8[i]);
  }
  return btoa(binary);
}

export const SAMPLE_BINARIES: SamplePE[] = [
  {
    id: 'sample-x64-dll',
    name: 'Windows 64-bit DLL (With Export Directory)',
    arch: 'x86-64 (AMD64)',
    subsystem: 'Windows GUI',
    description: 'Dynamic-Link Library with IMAGE_EXPORT_DIRECTORY exporting named and ordinal functions (CryptoPlugin.dll).',
    category: 'Modern x64',
    base64Data: bufferToBase64(createSampleDllWithExports()),
  },
  {
    id: 'sample-x64-gui',
    name: 'Windows 64-bit GUI Executable',
    arch: 'x86-64 (AMD64)',
    subsystem: 'Windows GUI',
    description: 'Modern 64-bit application with ASLR, DEP/NX, Authenticode signature, and Control Flow Guard enabled.',
    category: 'Modern x64',
    base64Data: bufferToBase64(createMinimalX64PE()),
  },
  {
    id: 'url-curl',
    name: 'Curl CLI (Official Windows Release)',
    arch: 'x86-64 (AMD64)',
    subsystem: 'Console (CUI)',
    description: 'Standalone curl.exe build distributed by curl.se for Windows 64-bit.',
    category: 'URL',
    url: 'https://curl.se/windows/dl-8.7.1_1/curl-8.7.1_1-win64-mingw.zip',
  },
  {
    id: 'url-ripgrep',
    name: 'Ripgrep (rg.exe) x86_64-pc-windows-msvc',
    arch: 'x86-64 (AMD64)',
    subsystem: 'Console (CUI)',
    description: 'High performance search utility compiled with Rust/MSVC for Windows 64-bit.',
    category: 'CLI Tool',
    url: 'https://github.com/BurntSushi/ripgrep/releases/download/14.1.0/ripgrep-14.1.0-x86_64-pc-windows-msvc.zip',
  },
  {
    id: 'url-procmon',
    name: 'Sysinternals Process Monitor (Procmon.exe)',
    arch: 'x86-64 (AMD64)',
    subsystem: 'Windows GUI',
    description: 'Official Microsoft Sysinternals live system monitoring utility.',
    category: 'Modern x64',
    url: 'https://download.sysinternals.com/files/ProcessMonitor.zip',
  },
];
