import React from 'react';
import { ParsedPE, ByteSpan } from '../lib/pe-parser';
import { Cpu, Terminal, Calendar, MapPin, Hash, ShieldCheck, Activity, Layers, Share2 } from 'lucide-react';

interface PeOverviewCardProps {
  pe: ParsedPE;
  onHighlightSpan: (span: ByteSpan | { start: number; end: number; name?: string }) => void;
}

export const PeOverviewCard: React.FC<PeOverviewCardProps> = ({ pe, onHighlightSpan }) => {
  const is64Bit = pe.optionalHeader?.is64Bit ?? false;

  return (
    <div className="space-y-6">
      {/* Export Directory Banner if present */}
      {pe.exportDirectory && (
        <div className="p-4 rounded-xl bg-teal-950/40 border border-teal-500/30 flex flex-wrap items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-lg bg-teal-500/20 text-teal-300">
              <Share2 className="w-4 h-4" />
            </div>
            <div>
              <span className="font-semibold text-teal-200">Export Directory Present: </span>
              <span className="text-white font-mono font-bold">{pe.exportDirectory.dllName}</span>
              <span className="text-teal-300/80 ml-1.5">
                ({pe.exportDirectory.functions.length} exported functions, Ordinal Base {pe.exportDirectory.base})
              </span>
            </div>
          </div>
          <button
            onClick={() =>
              pe.exportDirectory &&
              onHighlightSpan({
                start: pe.exportDirectory.directoryOffset,
                end: pe.exportDirectory.directoryOffset + 40,
                name: `IMAGE_EXPORT_DIRECTORY (${pe.exportDirectory.dllName})`,
              })
            }
            className="text-teal-300 hover:text-white font-mono text-[11px] underline underline-offset-2"
          >
            Locate 0x{pe.exportDirectory.directoryOffset.toString(16).toUpperCase()} in Hex
          </button>
        </div>
      )}

      {/* KPI Cards Strip */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 flex items-center gap-3">
          <div className="p-2 rounded-lg bg-indigo-500/10 text-indigo-400 shrink-0">
            <Cpu className="w-5 h-5" />
          </div>
          <div className="min-w-0">
            <div className="text-[11px] text-slate-400 uppercase tracking-wider">Architecture</div>
            <div className="text-sm font-semibold text-slate-100 truncate">
              {pe.fileHeader.machineName}
            </div>
          </div>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 flex items-center gap-3">
          <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 shrink-0">
            <Terminal className="w-5 h-5" />
          </div>
          <div className="min-w-0">
            <div className="text-[11px] text-slate-400 uppercase tracking-wider">Subsystem</div>
            <div className="text-sm font-semibold text-slate-100 truncate">
              {pe.optionalHeader?.subsystemName || 'N/A'}
            </div>
          </div>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 flex items-center gap-3">
          <div className="p-2 rounded-lg bg-amber-500/10 text-amber-400 shrink-0">
            <MapPin className="w-5 h-5" />
          </div>
          <div className="min-w-0">
            <div className="text-[11px] text-slate-400 uppercase tracking-wider">Entry Point (RVA)</div>
            <div className="text-sm font-semibold text-slate-100 font-mono tabular-nums truncate">
              {pe.optionalHeader ? `0x${pe.optionalHeader.addressOfEntryPoint.toString(16).toUpperCase()}` : 'None'}
            </div>
          </div>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 flex items-center gap-3">
          <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 shrink-0">
            <Calendar className="w-5 h-5" />
          </div>
          <div className="min-w-0">
            <div className="text-[11px] text-slate-400 uppercase tracking-wider">Build Timestamp</div>
            <div className="text-xs font-semibold text-slate-200 truncate" title={pe.fileHeader.timeDateString}>
              {pe.fileHeader.timeDateString}
            </div>
          </div>
        </div>
      </div>

      {/* Two Column Detailed Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left Column: DOS Header & COFF File Header */}
        <div className="space-y-6">
          {/* DOS Header Card */}
          <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden shadow-md">
            <div className="flex items-center justify-between px-4 py-3 bg-slate-950/60 border-b border-slate-800">
              <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-blue-400"></span>
                IMAGE_DOS_HEADER (64 Bytes)
              </h4>
              <button
                onClick={() => onHighlightSpan({ start: 0, end: 64, name: 'DOS Header' })}
                className="text-[11px] text-indigo-400 hover:text-indigo-300 font-medium"
              >
                Inspect 0x00 - 0x40
              </button>
            </div>

            <div className="p-4 space-y-2 text-xs font-mono">
              <div
                onClick={() => onHighlightSpan({ start: 0, end: 2, name: 'e_magic' })}
                className="flex items-center justify-between py-1.5 px-2 rounded hover:bg-slate-800/60 cursor-pointer transition-colors"
              >
                <span className="text-slate-400">e_magic (Signature):</span>
                <span className="text-indigo-300 font-semibold">
                  0x{pe.dosHeader.e_magic.toString(16).toUpperCase()} ('MZ')
                </span>
              </div>
              <div
                onClick={() => onHighlightSpan({ start: 60, end: 64, name: 'e_lfanew' })}
                className="flex items-center justify-between py-1.5 px-2 rounded hover:bg-slate-800/60 cursor-pointer transition-colors"
              >
                <span className="text-slate-400">e_lfanew (Offset to PE):</span>
                <span className="text-amber-300 font-semibold">
                  0x{pe.dosHeader.e_lfanew.toString(16).toUpperCase()} ({pe.dosHeader.e_lfanew} bytes)
                </span>
              </div>
              <div className="flex items-center justify-between py-1.5 px-2 text-slate-500 border-t border-slate-850">
                <span>e_cblp / e_cp:</span>
                <span>{pe.dosHeader.e_cblp} / {pe.dosHeader.e_cp}</span>
              </div>
              <div className="flex items-center justify-between py-1.5 px-2 text-slate-500">
                <span>e_crlc / e_cparhdr:</span>
                <span>{pe.dosHeader.e_crlc} / {pe.dosHeader.e_cparhdr}</span>
              </div>
              {pe.dosStubText && (
                <div
                  onClick={() => onHighlightSpan({ start: 64, end: pe.peSignatureOffset, name: 'DOS Stub' })}
                  className="mt-2 p-2 rounded bg-slate-950/80 border border-slate-850 text-slate-400 cursor-pointer hover:border-slate-700"
                >
                  <div className="text-[10px] text-slate-500 uppercase">DOS Stub Message</div>
                  <div className="text-slate-300 font-sans mt-0.5">{pe.dosStubText}</div>
                </div>
              )}
            </div>
          </div>

          {/* COFF File Header */}
          <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden shadow-md">
            <div className="flex items-center justify-between px-4 py-3 bg-slate-950/60 border-b border-slate-800">
              <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
                IMAGE_FILE_HEADER (COFF)
              </h4>
              <button
                onClick={() =>
                  onHighlightSpan({
                    start: pe.peSignatureOffset + 4,
                    end: pe.peSignatureOffset + 24,
                    name: 'COFF Header',
                  })
                }
                className="text-[11px] text-indigo-400 hover:text-indigo-300 font-medium"
              >
                Inspect at 0x{(pe.peSignatureOffset + 4).toString(16)}
              </button>
            </div>

            <div className="p-4 space-y-2 text-xs font-mono">
              <div className="flex items-center justify-between py-1.5 px-2 rounded hover:bg-slate-800/60">
                <span className="text-slate-400">Machine Architecture:</span>
                <span className="text-emerald-300 font-semibold">{pe.fileHeader.machineName}</span>
              </div>
              <div className="flex items-center justify-between py-1.5 px-2 rounded hover:bg-slate-800/60">
                <span className="text-slate-400">NumberOfSections:</span>
                <span className="text-slate-200 font-semibold">{pe.fileHeader.numberOfSections}</span>
              </div>
              <div className="flex items-center justify-between py-1.5 px-2 rounded hover:bg-slate-800/60">
                <span className="text-slate-400">TimeDateStamp:</span>
                <span className="text-slate-200">
                  0x{pe.fileHeader.timeDateStamp.toString(16).toUpperCase()}
                </span>
              </div>
              <div className="flex items-center justify-between py-1.5 px-2 rounded hover:bg-slate-800/60">
                <span className="text-slate-400">SizeOfOptionalHeader:</span>
                <span className="text-slate-200">{pe.fileHeader.sizeOfOptionalHeader} bytes</span>
              </div>
              <div className="flex items-center justify-between py-1.5 px-2 rounded hover:bg-slate-800/60">
                <span className="text-slate-400">Characteristics:</span>
                <span className="text-slate-200 font-semibold">
                  0x{pe.fileHeader.characteristics.toString(16).toUpperCase()}
                </span>
              </div>
              <div className="pt-2 border-t border-slate-850 flex flex-wrap gap-1">
                {pe.fileHeader.characteristicsList.map((c) => (
                  <span
                    key={c}
                    className="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] text-slate-300 border border-slate-700 font-mono"
                  >
                    {c}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Optional Header */}
        <div>
          {pe.optionalHeader ? (
            <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden shadow-md">
              <div className="flex items-center justify-between px-4 py-3 bg-slate-950/60 border-b border-slate-800">
                <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-indigo-400"></span>
                  IMAGE_OPTIONAL_HEADER ({is64Bit ? 'PE32+ 64-bit' : 'PE32 32-bit'})
                </h4>
                <button
                  onClick={() =>
                    onHighlightSpan({
                      start: pe.peSignatureOffset + 24,
                      end: pe.peSignatureOffset + 24 + pe.fileHeader.sizeOfOptionalHeader,
                      name: 'Optional Header',
                    })
                  }
                  className="text-[11px] text-indigo-400 hover:text-indigo-300 font-medium"
                >
                  Inspect Header
                </button>
              </div>

              <div className="p-4 space-y-2 text-xs font-mono divide-y divide-slate-850/60">
                <div className="pb-2 space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">Magic:</span>
                    <span className="text-indigo-300 font-semibold">
                      0x{pe.optionalHeader.magic.toString(16).toUpperCase()} ({is64Bit ? 'PE32+' : 'PE32'})
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">Linker Version:</span>
                    <span className="text-slate-200">
                      {pe.optionalHeader.majorLinkerVersion}.{pe.optionalHeader.minorLinkerVersion}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">ImageBase:</span>
                    <span className="text-amber-300 font-semibold">{pe.optionalHeader.imageBase}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">AddressOfEntryPoint (RVA):</span>
                    <span className="text-emerald-300 font-semibold">
                      0x{pe.optionalHeader.addressOfEntryPoint.toString(16).toUpperCase()}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">BaseOfCode:</span>
                    <span className="text-slate-300">
                      0x{pe.optionalHeader.baseOfCode.toString(16).toUpperCase()}
                    </span>
                  </div>
                </div>

                <div className="py-2 space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">SectionAlignment / FileAlignment:</span>
                    <span className="text-slate-200">
                      0x{pe.optionalHeader.sectionAlignment.toString(16)} / 0x{pe.optionalHeader.fileAlignment.toString(16)}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">SizeOfImage:</span>
                    <span className="text-slate-200">
                      0x{pe.optionalHeader.sizeOfImage.toString(16).toUpperCase()} ({(pe.optionalHeader.sizeOfImage / 1024).toFixed(1)} KB)
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">SizeOfHeaders:</span>
                    <span className="text-slate-200">
                      0x{pe.optionalHeader.sizeOfHeaders.toString(16).toUpperCase()} ({pe.optionalHeader.sizeOfHeaders} bytes)
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">Subsystem:</span>
                    <span className="text-slate-200 font-sans font-medium">
                      {pe.optionalHeader.subsystemName}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">DllCharacteristics:</span>
                    <span className="text-slate-200 font-semibold">
                      0x{pe.optionalHeader.dllCharacteristics.toString(16).toUpperCase()}
                    </span>
                  </div>
                </div>

                <div className="pt-2">
                  <div className="text-[11px] text-slate-400 mb-1.5">DllCharacteristics Flags:</div>
                  <div className="flex flex-wrap gap-1">
                    {pe.optionalHeader.dllCharacteristicsList.map((flag) => (
                      <span
                        key={flag}
                        className="px-1.5 py-0.5 rounded bg-indigo-950/60 text-indigo-300 border border-indigo-800/40 text-[10px]"
                      >
                        {flag}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="p-8 text-center text-slate-500 bg-slate-900 border border-slate-800 rounded-xl">
              No optional header present in this binary.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
