import React, { useState } from 'react';
import { ImportedModule } from '../lib/pe-parser';
import { FileCode2, Search, ChevronDown, ChevronRight, Hash } from 'lucide-react';

interface ImportsViewProps {
  imports?: ImportedModule[];
}

export const ImportsView: React.FC<ImportsViewProps> = ({ imports }) => {
  const [search, setSearch] = useState('');
  const [expandedModules, setExpandedModules] = useState<Record<string, boolean>>({
    0: true, // first module expanded by default
  });

  if (!imports || imports.length === 0) {
    return (
      <div className="p-8 text-center text-slate-500 bg-slate-900 border border-slate-800 rounded-xl">
        <FileCode2 className="w-8 h-8 mx-auto text-slate-600 mb-2" />
        <p className="text-sm font-medium text-slate-300">No Import Descriptors Found In Fetched Buffer</p>
        <p className="text-xs text-slate-500 mt-1 max-w-md mx-auto">
          The Import Table might reside in a section beyond the initial fetched range, or this executable has no external DLL imports.
        </p>
      </div>
    );
  }

  const toggleModule = (idx: number) => {
    setExpandedModules((prev) => ({ ...prev, [idx]: !prev[idx] }));
  };

  const filteredImports = imports.filter((mod) => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    if (mod.name.toLowerCase().includes(q)) return true;
    return mod.functions.some((f) => f.name.toLowerCase().includes(q));
  });

  const totalFunctions = imports.reduce((sum, m) => sum + m.functions.length, 0);

  return (
    <div className="space-y-4">
      {/* Top search & summary bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-3 rounded-xl bg-slate-900 border border-slate-800">
        <div className="flex items-center gap-2">
          <FileCode2 className="w-5 h-5 text-indigo-400" />
          <span className="text-sm font-semibold text-slate-100">
            Imported DLL Modules ({imports.length} DLLs, ~{totalFunctions} sampled APIs)
          </span>
        </div>

        <div className="relative">
          <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-500 pointer-events-none" />
          <input
            type="text"
            placeholder="Search DLL or function..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-56 pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-indigo-500"
          />
        </div>
      </div>

      {/* Accordion List of DLLs */}
      <div className="space-y-2">
        {filteredImports.map((mod, idx) => {
          const isExpanded = !!expandedModules[idx];
          return (
            <div
              key={mod.name + idx}
              className="border border-slate-800 rounded-xl bg-slate-900 overflow-hidden transition-all"
            >
              <button
                onClick={() => toggleModule(idx)}
                className="w-full flex items-center justify-between p-3.5 hover:bg-slate-800/40 text-left transition-colors"
              >
                <div className="flex items-center gap-2.5 font-mono">
                  {isExpanded ? (
                    <ChevronDown className="w-4 h-4 text-indigo-400" />
                  ) : (
                    <ChevronRight className="w-4 h-4 text-slate-500" />
                  )}
                  <span className="font-semibold text-sm text-slate-100">{mod.name}</span>
                </div>

                <div className="flex items-center gap-3 text-xs">
                  <span className="text-slate-400 font-mono">
                    {mod.functions.length} function{mod.functions.length === 1 ? '' : 's'}
                  </span>
                </div>
              </button>

              {isExpanded && mod.functions.length > 0 && (
                <div className="px-4 pb-4 pt-1 border-t border-slate-850 bg-slate-950/40">
                  <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2 mt-2">
                    {mod.functions.map((fn, fIdx) => (
                      <div
                        key={fIdx}
                        className="flex items-center justify-between p-2 rounded bg-slate-900/90 border border-slate-850 font-mono text-xs text-slate-300"
                      >
                        <span className="truncate mr-2 font-medium text-slate-200" title={fn.name}>
                          {fn.name}
                        </span>
                        {fn.hint !== undefined && (
                          <span className="text-[10px] text-slate-500 shrink-0 font-mono">
                            hint: {fn.hint}
                          </span>
                        )}
                        {fn.ordinal !== undefined && (
                          <span className="text-[10px] text-amber-400 shrink-0 flex items-center gap-0.5">
                            <Hash className="w-3 h-3" />
                            {fn.ordinal}
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
