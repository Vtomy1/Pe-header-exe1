import React, { useState } from 'react';
import { ExportDirectory, ExportFunction } from '../lib/pe-parser';
import { Share2, Search, ArrowUpRight, Hash, Calendar, Layers, Info, ExternalLink } from 'lucide-react';

interface ExportsViewProps {
  exportDirectory?: ExportDirectory;
  onHighlightExport?: (func: ExportFunction) => void;
  onHighlightDirectory?: () => void;
}

export const ExportsView: React.FC<ExportsViewProps> = ({
  exportDirectory,
  onHighlightExport,
  onHighlightDirectory,
}) => {
  const [search, setSearch] = useState('');

  if (!exportDirectory || exportDirectory.functions.length === 0) {
    return (
      <div className="p-8 text-center text-slate-500 bg-slate-900 border border-slate-800 rounded-xl space-y-2">
        <Share2 className="w-8 h-8 mx-auto text-slate-600 mb-2" />
        <h4 className="text-sm font-semibold text-slate-300">No Export Directory (IMAGE_EXPORT_DIRECTORY) Present</h4>
        <p className="text-xs text-slate-500 max-w-lg mx-auto leading-relaxed">
          Standard executable binaries (.exe) generally do not export functions unless designed as servers or plugins.
          Export directories are typically found in Dynamic Link Libraries (.dll), Control Panel applets (.cpl), or drivers (.sys).
        </p>
      </div>
    );
  }

  const filteredFunctions = exportDirectory.functions.filter((fn) => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    if (fn.name && fn.name.toLowerCase().includes(q)) return true;
    if (fn.forwarder && fn.forwarder.toLowerCase().includes(q)) return true;
    if (`#${fn.ordinal}`.includes(q) || `${fn.ordinal}` === q) return true;
    if (`0x${fn.rva.toString(16)}`.toLowerCase().includes(q)) return true;
    return false;
  });

  const namedCount = exportDirectory.functions.filter((f) => !!f.name).length;
  const ordinalOnlyCount = exportDirectory.functions.length - namedCount;
  const forwarderCount = exportDirectory.functions.filter((f) => f.isForwarder).length;

  return (
    <div className="space-y-6">
      {/* Overview Card */}
      <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-850">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-teal-500/10 border border-teal-500/20 text-teal-400 shrink-0">
              <Share2 className="w-6 h-6" />
            </div>
            <div>
              <div className="text-[11px] text-slate-400 uppercase tracking-wider">Module Export Identifier</div>
              <h3 className="text-lg font-bold text-white font-mono flex items-center gap-2">
                <span>{exportDirectory.dllName}</span>
                <span className="text-xs font-normal text-slate-400 font-sans">
                  (Ordinal Base: {exportDirectory.base})
                </span>
              </h3>
            </div>
          </div>

          <button
            onClick={onHighlightDirectory}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-teal-300 border border-slate-700 text-xs font-medium transition-colors self-start sm:self-auto"
          >
            <span>Inspect Table in Hex</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Export Stats Strip */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
          <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-850">
            <div className="text-slate-400">Total Exports (EAT)</div>
            <div className="text-base font-bold text-slate-100 font-mono mt-0.5 tabular-nums">
              {exportDirectory.numberOfFunctions}
            </div>
          </div>

          <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-850">
            <div className="text-slate-400">Named Exports (ENPT)</div>
            <div className="text-base font-bold text-teal-300 font-mono mt-0.5 tabular-nums">
              {namedCount}
            </div>
          </div>

          <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-850">
            <div className="text-slate-400">Ordinal-Only Exports</div>
            <div className="text-base font-bold text-amber-300 font-mono mt-0.5 tabular-nums">
              {ordinalOnlyCount}
            </div>
          </div>

          <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-850">
            <div className="text-slate-400">Forwarded Functions</div>
            <div className="text-base font-bold text-indigo-300 font-mono mt-0.5 tabular-nums">
              {forwarderCount}
            </div>
          </div>
        </div>

        {/* Directory Metadata Details */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-[11px] font-mono text-slate-400 pt-1">
          <div>
            <span className="text-slate-500">AddressOfFunctions: </span>
            <span className="text-slate-200">
              0x{exportDirectory.addressOfFunctions.toString(16).padStart(8, '0').toUpperCase()}
            </span>
          </div>
          <div>
            <span className="text-slate-500">AddressOfNames: </span>
            <span className="text-slate-200">
              0x{exportDirectory.addressOfNames.toString(16).padStart(8, '0').toUpperCase()}
            </span>
          </div>
          <div>
            <span className="text-slate-500">AddressOfNameOrdinals: </span>
            <span className="text-slate-200">
              0x{exportDirectory.addressOfNameOrdinals.toString(16).padStart(8, '0').toUpperCase()}
            </span>
          </div>
        </div>
      </div>

      {/* Search and Table */}
      <div className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="text-xs text-slate-400 font-medium">
            Exported Functions List ({filteredFunctions.length} of {exportDirectory.functions.length})
          </div>

          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-500 pointer-events-none" />
            <input
              type="text"
              placeholder="Search export name, ordinal, or forwarder..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-64 pl-8 pr-3 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-teal-500"
            />
          </div>
        </div>

        {/* Table of Functions */}
        <div className="overflow-x-auto border border-slate-800 rounded-xl bg-slate-900 shadow-lg">
          <table className="w-full text-left text-xs border-collapse font-mono">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/70 text-slate-400">
                <th className="py-2.5 px-3 w-20">Ordinal</th>
                <th className="py-2.5 px-3">Function Name</th>
                <th className="py-2.5 px-3">Target / Entry Point (RVA)</th>
                <th className="py-2.5 px-3">Type</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-850 text-slate-300">
              {filteredFunctions.map((fn) => (
                <tr key={fn.ordinal} className="hover:bg-slate-800/40 transition-colors">
                  {/* Ordinal */}
                  <td className="py-2 px-3 text-slate-400 font-semibold tabular-nums">
                    <span className="flex items-center gap-0.5 text-teal-400">
                      <Hash className="w-3 h-3" />
                      {fn.ordinal}
                    </span>
                  </td>

                  {/* Function Name */}
                  <td className="py-2 px-3 font-medium">
                    {fn.name ? (
                      <span className="text-slate-100 font-bold">{fn.name}</span>
                    ) : (
                      <span className="text-amber-400/80 italic font-sans text-[11px]">
                        [Exported by Ordinal Only]
                      </span>
                    )}
                  </td>

                  {/* RVA or Forwarder */}
                  <td className="py-2 px-3 tabular-nums">
                    {fn.isForwarder ? (
                      <div className="flex items-center gap-1.5 text-indigo-300">
                        <ArrowUpRight className="w-3.5 h-3.5 text-indigo-400 shrink-0" />
                        <span className="font-semibold">{fn.forwarder}</span>
                        <span className="text-[10px] text-slate-500">(Forwarded)</span>
                      </div>
                    ) : (
                      <span className="text-teal-300">
                        0x{fn.rva.toString(16).padStart(8, '0').toUpperCase()}
                      </span>
                    )}
                  </td>

                  {/* Type */}
                  <td className="py-2 px-3 font-sans">
                    {fn.isForwarder ? (
                      <span className="px-1.5 py-0.5 rounded bg-indigo-950/60 text-indigo-300 border border-indigo-800/40 text-[10px] font-medium">
                        Forwarder
                      </span>
                    ) : fn.name ? (
                      <span className="px-1.5 py-0.5 rounded bg-teal-950/60 text-teal-300 border border-teal-800/40 text-[10px] font-medium">
                        Named Export
                      </span>
                    ) : (
                      <span className="px-1.5 py-0.5 rounded bg-amber-950/60 text-amber-300 border border-amber-800/40 text-[10px] font-medium">
                        Ordinal Only
                      </span>
                    )}
                  </td>

                  {/* Inspect action */}
                  <td className="py-2 px-3 text-right">
                    <button
                      onClick={() => onHighlightExport?.(fn)}
                      className="text-slate-400 hover:text-teal-300 text-[11px] underline underline-offset-2 transition-colors"
                    >
                      Locate
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
