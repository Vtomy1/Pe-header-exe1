import React from 'react';
import { SectionHeader } from '../lib/pe-parser';
import { Layers, AlertTriangle, Eye, Shield } from 'lucide-react';

interface SectionsTableProps {
  sections: SectionHeader[];
  onSelectSection?: (section: SectionHeader) => void;
  selectedSectionIndex?: number | null;
}

export const SectionsTable: React.FC<SectionsTableProps> = ({
  sections,
  onSelectSection,
  selectedSectionIndex,
}) => {
  if (sections.length === 0) {
    return (
      <div className="p-8 text-center text-slate-500 bg-slate-900 border border-slate-800 rounded-xl">
        No section headers found in this executable.
      </div>
    );
  }

  const formatBytes = (bytes: number) => {
    if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${bytes} B`;
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Layers className="w-5 h-5 text-indigo-400" />
          <h3 className="text-sm font-semibold text-slate-100">
            PE Section Headers ({sections.length} Sections)
          </h3>
        </div>
        <span className="text-xs text-slate-400">
          Click any section row to locate in Hex Inspector
        </span>
      </div>

      <div className="overflow-x-auto border border-slate-800 rounded-xl bg-slate-900 shadow-lg">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="border-b border-slate-800 bg-slate-950/70 text-slate-400 font-mono">
              <th className="py-2.5 px-3">#</th>
              <th className="py-2.5 px-3 font-semibold text-slate-200">Name</th>
              <th className="py-2.5 px-3">Virtual Size</th>
              <th className="py-2.5 px-3">Virtual Address (RVA)</th>
              <th className="py-2.5 px-3">Raw Size</th>
              <th className="py-2.5 px-3">Raw File Offset</th>
              <th className="py-2.5 px-3">Perms</th>
              <th className="py-2.5 px-3">Entropy (0-8)</th>
              <th className="py-2.5 px-3 text-right">Characteristics</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-850 font-mono">
            {sections.map((sec, idx) => {
              const isSelected = selectedSectionIndex === idx;
              const hasHighEntropy = sec.entropyStatus === 'high';

              return (
                <tr
                  key={sec.name + idx}
                  onClick={() => onSelectSection?.(sec)}
                  className={`cursor-pointer transition-colors ${
                    isSelected
                      ? 'bg-indigo-950/40 text-indigo-200 ring-1 ring-inset ring-indigo-500/50'
                      : 'hover:bg-slate-800/40 text-slate-300'
                  }`}
                >
                  <td className="py-2 px-3 text-slate-500">{idx}</td>
                  <td className="py-2 px-3 font-bold text-slate-100 font-sans flex items-center gap-1.5">
                    <span className="font-mono text-indigo-300">{sec.name}</span>
                    {hasHighEntropy && (
                      <span
                        title="High entropy (> 7.1) suggests compression or encryption (packed payload or encrypted code)"
                        className="text-amber-400"
                      >
                        <AlertTriangle className="w-3.5 h-3.5" />
                      </span>
                    )}
                  </td>
                  <td className="py-2 px-3 tabular-nums">
                    0x{sec.virtualSize.toString(16).toUpperCase()} ({formatBytes(sec.virtualSize)})
                  </td>
                  <td className="py-2 px-3 text-indigo-400 tabular-nums">
                    0x{sec.virtualAddress.toString(16).padStart(8, '0').toUpperCase()}
                  </td>
                  <td className="py-2 px-3 tabular-nums">
                    0x{sec.sizeOfRawData.toString(16).toUpperCase()} ({formatBytes(sec.sizeOfRawData)})
                  </td>
                  <td className="py-2 px-3 text-slate-400 tabular-nums">
                    0x{sec.pointerToRawData.toString(16).padStart(8, '0').toUpperCase()}
                  </td>
                  <td className="py-2 px-3">
                    <span
                      className={`px-1.5 py-0.5 rounded text-[11px] font-bold ${
                        sec.permissions.includes('X')
                          ? 'bg-rose-950/60 text-rose-300 border border-rose-800/40'
                          : sec.permissions.includes('W')
                          ? 'bg-amber-950/60 text-amber-300 border border-amber-800/40'
                          : 'bg-blue-950/60 text-blue-300 border border-blue-800/40'
                      }`}
                    >
                      {sec.permissions}
                    </span>
                  </td>
                  <td className="py-2 px-3">
                    {sec.entropy !== undefined ? (
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full ${
                              hasHighEntropy
                                ? 'bg-amber-400'
                                : sec.entropy < 2.0
                                ? 'bg-slate-600'
                                : 'bg-emerald-400'
                            }`}
                            style={{ width: `${Math.min(100, (sec.entropy / 8) * 100)}%` }}
                          />
                        </div>
                        <span className="tabular-nums text-[11px] text-slate-300">
                          {sec.entropy.toFixed(2)}
                        </span>
                      </div>
                    ) : (
                      <span className="text-slate-600 text-[11px]">N/A</span>
                    )}
                  </td>
                  <td className="py-2 px-3 text-right text-slate-400">
                    <span className="text-[11px] truncate max-w-[150px] inline-block" title={sec.flagsList.join(', ')}>
                      {sec.flagsList.join(' | ') || `0x${sec.characteristics.toString(16)}`}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};
