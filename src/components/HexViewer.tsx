import React, { useState, useMemo } from 'react';
import { ByteSpan } from '../lib/pe-parser';
import { Search, Copy, Check, ChevronLeft, ChevronRight } from 'lucide-react';

interface HexViewerProps {
  data: Uint8Array;
  spans: ByteSpan[];
  highlightSpan?: { start: number; end: number; name?: string } | null;
  onSelectByte?: (offset: number) => void;
}

const CATEGORY_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  dos: { bg: 'bg-blue-950/60', text: 'text-blue-300', border: 'border-blue-500/40' },
  dos_stub: { bg: 'bg-slate-900', text: 'text-slate-400', border: 'border-slate-700' },
  rich: { bg: 'bg-purple-950/60', text: 'text-purple-300', border: 'border-purple-500/40' },
  nt_sig: { bg: 'bg-amber-950/70', text: 'text-amber-300', border: 'border-amber-500/50' },
  file_header: { bg: 'bg-emerald-950/60', text: 'text-emerald-300', border: 'border-emerald-500/40' },
  optional_header: { bg: 'bg-indigo-950/60', text: 'text-indigo-300', border: 'border-indigo-500/40' },
  data_dirs: { bg: 'bg-cyan-950/60', text: 'text-cyan-300', border: 'border-cyan-500/40' },
  export_dir: { bg: 'bg-teal-950/60', text: 'text-teal-300', border: 'border-teal-500/40' },
  section_headers: { bg: 'bg-rose-950/60', text: 'text-rose-300', border: 'border-rose-500/40' },
  section_data: { bg: 'bg-teal-950/60', text: 'text-teal-300', border: 'border-teal-500/40' },
  other: { bg: 'bg-slate-900', text: 'text-slate-400', border: 'border-slate-700' },
};

export const HexViewer: React.FC<HexViewerProps> = ({
  data,
  spans,
  highlightSpan,
  onSelectByte,
}) => {
  const [page, setPage] = useState(0);
  const [pageSize] = useState(512); // 32 lines of 16 bytes
  const [hoveredOffset, setHoveredOffset] = useState<number | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [copied, setCopied] = useState(false);

  const totalPages = Math.max(1, Math.ceil(data.length / pageSize));
  const currentPage = Math.min(page, totalPages - 1);

  // Jump to page containing highlightSpan if given
  React.useEffect(() => {
    if (highlightSpan && highlightSpan.start >= 0) {
      const targetPage = Math.floor(highlightSpan.start / pageSize);
      if (targetPage !== currentPage && targetPage < totalPages) {
        setPage(targetPage);
      }
    }
  }, [highlightSpan, pageSize, totalPages, currentPage]);

  const pageStart = currentPage * pageSize;
  const pageEnd = Math.min(data.length, pageStart + pageSize);
  const pageBytes = useMemo(() => data.subarray(pageStart, pageEnd), [data, pageStart, pageEnd]);

  // Build rows of 16 bytes
  const rows = useMemo(() => {
    const r = [];
    for (let i = 0; i < pageBytes.length; i += 16) {
      const rowOffset = pageStart + i;
      const rowBytes = pageBytes.subarray(i, Math.min(i + 16, pageBytes.length));
      r.push({ rowOffset, bytes: Array.from(rowBytes) });
    }
    return r;
  }, [pageBytes, pageStart]);

  // Find span for given offset
  const getSpanForOffset = (offset: number): ByteSpan | undefined => {
    return spans.find((s) => offset >= s.start && offset < s.end);
  };

  const hoveredSpan = hoveredOffset !== null ? getSpanForOffset(hoveredOffset) : null;

  const handleCopyPageHex = () => {
    let hexStr = '';
    for (let i = 0; i < pageBytes.length; i++) {
      hexStr += pageBytes[i].toString(16).padStart(2, '0').toUpperCase() + ' ';
      if ((i + 1) % 16 === 0) hexStr += '\n';
    }
    navigator.clipboard.writeText(hexStr);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="flex flex-col border border-slate-800 rounded-xl bg-slate-900/90 overflow-hidden shadow-xl">
      {/* Top Hex Viewer Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 bg-slate-900 border-b border-slate-800 text-xs">
        <div className="flex items-center gap-2">
          <span className="font-semibold text-slate-200">Raw Hex Inspector</span>
          <span className="text-slate-500">·</span>
          <span className="text-slate-400 font-mono tabular-nums">
            {data.length.toLocaleString()} bytes total ({totalPages} pages)
          </span>
          {highlightSpan && (
            <div className="flex items-center gap-1.5 ml-2 px-2 py-0.5 rounded bg-indigo-500/20 border border-indigo-500/30 text-indigo-300">
              <span className="font-mono">
                0x{highlightSpan.start.toString(16).toUpperCase()} - 0x{highlightSpan.end.toString(16).toUpperCase()}
              </span>
              {highlightSpan.name && <span>({highlightSpan.name})</span>}
            </div>
          )}
        </div>

        <div className="flex items-center gap-3">
          {/* Quick Search */}
          <div className="relative flex items-center">
            <Search className="w-3.5 h-3.5 absolute left-2 text-slate-500 pointer-events-none" />
            <input
              type="text"
              placeholder="Filter hex/offset..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-36 pl-7 pr-2 py-1 bg-slate-950 border border-slate-800 rounded text-xs text-slate-300 placeholder-slate-600 focus:outline-none focus:border-indigo-500"
            />
          </div>

          {/* Copy Button */}
          <button
            onClick={handleCopyPageHex}
            className="flex items-center gap-1 px-2.5 py-1 text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded transition-colors whitespace-nowrap"
            title="Copy current page hex values"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied' : 'Copy Hex'}</span>
          </button>

          {/* Pagination Controls */}
          <div className="flex items-center gap-1.5 font-mono text-slate-400">
            <button
              disabled={currentPage === 0}
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              className="p-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:pointer-events-none text-slate-300"
              aria-label="Previous Page"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="px-1 text-slate-300 tabular-nums">
              {currentPage + 1} / {totalPages}
            </span>
            <button
              disabled={currentPage >= totalPages - 1}
              onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
              className="p-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:pointer-events-none text-slate-300"
              aria-label="Next Page"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Legend Bar */}
      <div className="flex flex-wrap items-center gap-2 px-4 py-2 bg-slate-950/60 border-b border-slate-800/80 text-[11px] text-slate-400">
        <span className="text-slate-500 font-medium">Regions:</span>
        <span className="flex items-center gap-1 px-1.5 py-0.5 rounded bg-blue-950/60 border border-blue-500/40 text-blue-300">
          DOS Header
        </span>
        <span className="flex items-center gap-1 px-1.5 py-0.5 rounded bg-purple-950/60 border border-purple-500/40 text-purple-300">
          Rich Header
        </span>
        <span className="flex items-center gap-1 px-1.5 py-0.5 rounded bg-amber-950/70 border border-amber-500/50 text-amber-300">
          PE Signature
        </span>
        <span className="flex items-center gap-1 px-1.5 py-0.5 rounded bg-emerald-950/60 border border-emerald-500/40 text-emerald-300">
          COFF Header
        </span>
        <span className="flex items-center gap-1 px-1.5 py-0.5 rounded bg-indigo-950/60 border border-indigo-500/40 text-indigo-300">
          Optional Header
        </span>
        <span className="flex items-center gap-1 px-1.5 py-0.5 rounded bg-cyan-950/60 border border-cyan-500/40 text-cyan-300">
          Data Directories
        </span>
        <span className="flex items-center gap-1 px-1.5 py-0.5 rounded bg-teal-950/60 border border-teal-500/40 text-teal-300">
          Export Table
        </span>
        <span className="flex items-center gap-1 px-1.5 py-0.5 rounded bg-rose-950/60 border border-rose-500/40 text-rose-300">
          Section Headers
        </span>
      </div>

      {/* Hex Dump Table */}
      <div className="overflow-x-auto p-3 font-mono text-xs select-text">
        <table className="w-full border-collapse">
          <thead>
            <tr className="text-slate-500 border-b border-slate-800/60 select-none">
              <th className="text-left font-normal py-1 pr-4 w-24">Offset</th>
              <th className="text-left font-normal py-1 pr-6">
                <span className="inline-grid grid-cols-16 gap-1 w-full max-w-[420px]">
                  {Array.from({ length: 16 }, (_, i) => (
                    <span key={i} className="text-center w-6">
                      {i.toString(16).toUpperCase().padStart(2, '0')}
                    </span>
                  ))}
                </span>
              </th>
              <th className="text-left font-normal py-1 pl-4">Decoded ASCII</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-850">
            {rows.map(({ rowOffset, bytes }) => {
              return (
                <tr key={rowOffset} className="hover:bg-slate-800/30 transition-colors">
                  {/* Offset Column */}
                  <td className="text-slate-500 py-1 pr-4 whitespace-nowrap select-none font-semibold tabular-nums">
                    {rowOffset.toString(16).padStart(8, '0').toUpperCase()}
                  </td>

                  {/* 16 Hex Bytes */}
                  <td className="py-1 pr-6 whitespace-nowrap">
                    <div className="inline-grid grid-cols-16 gap-1 max-w-[420px]">
                      {Array.from({ length: 16 }, (_, colIdx) => {
                        if (colIdx >= bytes.length) {
                          return <span key={colIdx} className="w-6 inline-block text-slate-800 text-center">..</span>;
                        }

                        const byteOffset = rowOffset + colIdx;
                        const byteVal = bytes[colIdx];
                        const hexStr = byteVal.toString(16).padStart(2, '0').toUpperCase();
                        const span = getSpanForOffset(byteOffset);
                        const isHovered = hoveredOffset === byteOffset;
                        const isHighlighted =
                          highlightSpan &&
                          byteOffset >= highlightSpan.start &&
                          byteOffset < highlightSpan.end;

                        let colorClass = 'text-slate-400 hover:text-white';
                        if (span && CATEGORY_COLORS[span.category]) {
                          colorClass = `${CATEGORY_COLORS[span.category].text} ${CATEGORY_COLORS[span.category].bg}`;
                        }

                        if (isHighlighted) {
                          colorClass = 'bg-amber-400 text-slate-950 font-bold ring-1 ring-amber-300';
                        } else if (isHovered) {
                          colorClass = 'bg-white text-slate-950 font-bold ring-1 ring-white';
                        }

                        return (
                          <span
                            key={colIdx}
                            onMouseEnter={() => setHoveredOffset(byteOffset)}
                            onMouseLeave={() => setHoveredOffset(null)}
                            onClick={() => onSelectByte?.(byteOffset)}
                            className={`w-6 text-center cursor-pointer rounded px-0.5 py-0.5 transition-all text-[11px] ${colorClass}`}
                          >
                            {hexStr}
                          </span>
                        );
                      })}
                    </div>
                  </td>

                  {/* ASCII Representation */}
                  <td className="py-1 pl-4 text-slate-400 whitespace-nowrap">
                    <div className="flex tracking-wider">
                      {bytes.map((byteVal, colIdx) => {
                        const byteOffset = rowOffset + colIdx;
                        const isHovered = hoveredOffset === byteOffset;
                        const isHighlighted =
                          highlightSpan &&
                          byteOffset >= highlightSpan.start &&
                          byteOffset < highlightSpan.end;

                        const isPrintable = byteVal >= 32 && byteVal <= 126;
                        const char = isPrintable ? String.fromCharCode(byteVal) : '·';

                        let charColor = isPrintable ? 'text-slate-300' : 'text-slate-600';
                        if (isHighlighted) {
                          charColor = 'bg-amber-400 text-slate-950 font-bold px-0.5 rounded';
                        } else if (isHovered) {
                          charColor = 'bg-white text-slate-950 font-bold px-0.5 rounded';
                        }

                        return (
                          <span
                            key={colIdx}
                            onMouseEnter={() => setHoveredOffset(byteOffset)}
                            onMouseLeave={() => setHoveredOffset(null)}
                            className={`inline-block w-2 text-center cursor-pointer ${charColor}`}
                          >
                            {char}
                          </span>
                        );
                      })}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Hover Inspector Footer */}
      <div className="flex items-center justify-between px-4 py-2 bg-slate-950 border-t border-slate-800 text-xs">
        {hoveredOffset !== null && hoveredOffset < data.length ? (
          <div className="flex items-center gap-3 text-slate-300 font-mono">
            <div>
              <span className="text-slate-500">Offset: </span>
              <span className="text-indigo-400 font-semibold">
                0x{hoveredOffset.toString(16).toUpperCase().padStart(4, '0')} ({hoveredOffset})
              </span>
            </div>
            <span>·</span>
            <div>
              <span className="text-slate-500">Value: </span>
              <span className="text-amber-400 font-semibold">
                0x{data[hoveredOffset].toString(16).padStart(2, '0').toUpperCase()} ({data[hoveredOffset]})
              </span>
            </div>
            <span>·</span>
            <div>
              <span className="text-slate-500">ASCII: </span>
              <span className="text-emerald-400 font-semibold">
                {data[hoveredOffset] >= 32 && data[hoveredOffset] <= 126
                  ? `'${String.fromCharCode(data[hoveredOffset])}'`
                  : 'Non-printable'}
              </span>
            </div>
            {hoveredSpan && (
              <>
                <span>·</span>
                <div className="text-slate-300">
                  <span className="text-slate-500">Section/Field: </span>
                  <span className="text-indigo-300 font-medium">{hoveredSpan.name}</span>
                  {hoveredSpan.description && (
                    <span className="text-slate-500 text-[11px] ml-1">({hoveredSpan.description})</span>
                  )}
                </div>
              </>
            )}
          </div>
        ) : (
          <span className="text-slate-500 italic">
            Hover over any hex byte or ASCII character to inspect offset, value, and associated PE structure.
          </span>
        )}
      </div>
    </div>
  );
};
