import React from 'react';
import { DataDirectory } from '../lib/pe-parser';
import { FolderGit2, CheckCircle2, Minus } from 'lucide-react';

interface DataDirectoriesTableProps {
  directories: DataDirectory[];
  onSelectDirectory?: (dir: DataDirectory) => void;
}

export const DataDirectoriesTable: React.FC<DataDirectoriesTableProps> = ({
  directories,
  onSelectDirectory,
}) => {
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <FolderGit2 className="w-5 h-5 text-indigo-400" />
          <h3 className="text-sm font-semibold text-slate-100">IMAGE_DATA_DIRECTORY Table</h3>
        </div>
        <span className="text-xs text-slate-400">
          Standard 16 PE data directories referencing tables in sections
        </span>
      </div>

      <div className="overflow-x-auto border border-slate-800 rounded-xl bg-slate-900 shadow-lg">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="border-b border-slate-800 bg-slate-950/70 text-slate-400 font-mono">
              <th className="py-2.5 px-3">#</th>
              <th className="py-2.5 px-3 font-semibold text-slate-200">Directory Entry</th>
              <th className="py-2.5 px-3">Virtual Address (RVA)</th>
              <th className="py-2.5 px-3">Size (Bytes)</th>
              <th className="py-2.5 px-3">Mapped Section</th>
              <th className="py-2.5 px-3 text-right">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-850 font-mono">
            {directories.map((dir) => {
              const isPresent = dir.virtualAddress > 0 && dir.size > 0;

              return (
                <tr
                  key={dir.index}
                  onClick={() => isPresent && onSelectDirectory?.(dir)}
                  className={`transition-colors ${
                    isPresent
                      ? 'cursor-pointer hover:bg-slate-800/40 text-slate-200'
                      : 'text-slate-500 opacity-60'
                  }`}
                >
                  <td className="py-2 px-3 text-slate-500">{dir.index}</td>
                  <td className="py-2 px-3 font-sans font-medium">
                    <span className={isPresent ? 'text-indigo-300 font-semibold' : 'text-slate-400'}>
                      {dir.name}
                    </span>
                  </td>
                  <td className="py-2 px-3 tabular-nums">
                    {dir.virtualAddress > 0 ? (
                      <span className="text-indigo-400">
                        0x{dir.virtualAddress.toString(16).padStart(8, '0').toUpperCase()}
                        {dir.index === 4 && <span className="text-slate-500 text-[10px] ml-1">(File Offset)</span>}
                      </span>
                    ) : (
                      '0x00000000'
                    )}
                  </td>
                  <td className="py-2 px-3 tabular-nums">
                    {dir.size > 0 ? (
                      <span>
                        0x{dir.size.toString(16).toUpperCase()}{' '}
                        <span className="text-slate-400">
                          ({dir.size >= 1024 ? `${(dir.size / 1024).toFixed(1)} KB` : `${dir.size} B`})
                        </span>
                      </span>
                    ) : (
                      '0'
                    )}
                  </td>
                  <td className="py-2 px-3">
                    {dir.sectionName ? (
                      <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 text-[11px] font-semibold border border-slate-700">
                        {dir.sectionName}
                      </span>
                    ) : (
                      <span className="text-slate-600">—</span>
                    )}
                  </td>
                  <td className="py-2 px-3 text-right font-sans">
                    {isPresent ? (
                      <span className="inline-flex items-center gap-1 text-emerald-400 text-xs font-medium">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>Present</span>
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-slate-600 text-xs">
                        <Minus className="w-3 h-3" />
                        <span>Empty</span>
                      </span>
                    )}
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
