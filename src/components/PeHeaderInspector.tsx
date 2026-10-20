import React, { useState, useEffect, useRef } from 'react';
import { parsePE, ParsedPE, ByteSpan, SectionHeader, DataDirectory } from '../lib/pe-parser';
import { SAMPLE_BINARIES, SamplePE } from '../lib/sample-binaries';
import { PeOverviewCard } from './PeOverviewCard';
import { HexViewer } from './HexViewer';
import { SectionsTable } from './SectionsTable';
import { DataDirectoriesTable } from './DataDirectoriesTable';
import { SecurityChecklist } from './SecurityChecklist';
import { ImportsView } from './ImportsView';
import { RichHeaderView } from './RichHeaderView';
import { ExportsView } from './ExportsView';
import { ExportModal } from './ExportModal';
import {
  Globe,
  Upload,
  ArrowRight,
  Loader2,
  FileCode,
  Shield,
  Layers,
  FolderGit2,
  Binary,
  Code2,
  FileCheck,
  AlertCircle,
  Download,
  Share2,
} from 'lucide-react';

export const PeHeaderInspector: React.FC = () => {
  const [urlInput, setUrlInput] = useState('');
  const [activeUrl, setActiveUrl] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [parsedPe, setParsedPe] = useState<ParsedPE | null>(null);
  const [activeTab, setActiveTab] = useState<
    'overview' | 'hex' | 'sections' | 'directories' | 'exports' | 'security' | 'imports' | 'rich'
  >('overview');

  const [highlightSpan, setHighlightSpan] = useState<{
    start: number;
    end: number;
    name?: string;
  } | null>(null);

  const [selectedSectionIndex, setSelectedSectionIndex] = useState<number | null>(null);
  const [isExportOpen, setIsExportOpen] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Load the initial 64-bit authentic PE sample on mount
  useEffect(() => {
    loadSample(SAMPLE_BINARIES[0]);
  }, []);

  const loadSample = (sample: SamplePE) => {
    setError(null);
    if (sample.base64Data) {
      try {
        const binStr = atob(sample.base64Data);
        const bytes = new Uint8Array(binStr.length);
        for (let i = 0; i < binStr.length; i++) {
          bytes[i] = binStr.charCodeAt(i);
        }
        const pe = parsePE(bytes);
        setParsedPe(pe);
        setActiveUrl(sample.name);
        setUrlInput(sample.url || '');
        setHighlightSpan(null);
      } catch (err: unknown) {
        setError(`Failed to load sample: ${err instanceof Error ? err.message : String(err)}`);
      }
    } else if (sample.url) {
      setUrlInput(sample.url);
      fetchUrl(sample.url);
    }
  };

  const fetchUrl = async (targetUrl: string) => {
    const trimmed = targetUrl.trim();
    if (!trimmed) {
      setError('Please enter a valid Windows executable URL.');
      return;
    }

    setLoading(true);
    setError(null);
    setHighlightSpan(null);

    try {
      // 1. First attempt backend proxy with Range: bytes=0-65535
      const res = await fetch('/api/fetch-pe-header', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: trimmed, maxBytes: 131072 }), // 128KB is plenty for all PE headers
      });

      if (res.ok) {
        const data = await res.json();
        if (data.success && data.dataBase64) {
          const binStr = atob(data.dataBase64);
          const bytes = new Uint8Array(binStr.length);
          for (let i = 0; i < binStr.length; i++) {
            bytes[i] = binStr.charCodeAt(i);
          }
          const pe = parsePE(bytes);
          if (!pe.isValidPE) {
            setError(pe.errorMessage || 'Target URL did not return a valid Windows PE header (MZ signature missing).');
          } else {
            setParsedPe(pe);
            setActiveUrl(trimmed);
          }
          setLoading(false);
          return;
        } else {
          throw new Error(data.error || 'Server could not fetch target binary header.');
        }
      }

      // If server returned non-200, try client direct fetch as fallback (for CORS enabled servers)
      const directRes = await fetch(trimmed, {
        headers: { Range: 'bytes=0-65535' },
      });

      if (!directRes.ok && directRes.status !== 206) {
        throw new Error(`Failed to fetch URL. HTTP status ${directRes.status}`);
      }

      const arrayBuf = await directRes.arrayBuffer();
      const pe = parsePE(new Uint8Array(arrayBuf));
      if (!pe.isValidPE) {
        setError(pe.errorMessage || 'Invalid Windows executable format (Missing 0x5A4D MZ header).');
      } else {
        setParsedPe(pe);
        setActiveUrl(trimmed);
      }
    } catch (err: unknown) {
      setError(
        `Unable to fetch or parse PE header from "${trimmed}". Cause: ${
          err instanceof Error ? err.message : String(err)
        }. Ensure the URL is accessible and points to a Windows .exe/.dll binary.`
      );
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setError(null);
    setLoading(true);

    const reader = new FileReader();
    reader.onload = () => {
      try {
        const buf = reader.result as ArrayBuffer;
        const pe = parsePE(new Uint8Array(buf));
        if (!pe.isValidPE) {
          setError(pe.errorMessage || 'Selected file is not a valid Windows executable.');
        } else {
          setParsedPe(pe);
          setActiveUrl(`Local file: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`);
          setUrlInput('');
          setHighlightSpan(null);
        }
      } catch (err: unknown) {
        setError(`Failed to read file: ${err instanceof Error ? err.message : String(err)}`);
      } finally {
        setLoading(false);
      }
    };
    reader.onerror = () => {
      setError('Error reading local file.');
      setLoading(false);
    };

    // Read up to 512KB for headers
    const slice = file.slice(0, 524288);
    reader.readAsArrayBuffer(slice);
  };

  const handleSelectSection = (sec: SectionHeader) => {
    setSelectedSectionIndex(sec.index);
    setHighlightSpan({
      start: sec.headerOffset,
      end: sec.headerOffset + 40,
      name: `Section Header: ${sec.name}`,
    });
    setActiveTab('hex');
  };

  const handleSelectDirectory = (dir: DataDirectory) => {
    if (parsedPe?.optionalHeader) {
      const optOffset = parsedPe.peSignatureOffset + 24;
      const is64 = parsedPe.optionalHeader.is64Bit;
      const dirOffset = (is64 ? optOffset + 112 : optOffset + 96) + dir.index * 8;
      setHighlightSpan({
        start: dirOffset,
        end: dirOffset + 8,
        name: `Data Directory: ${dir.name}`,
      });
      setActiveTab('hex');
    }
  };

  const handleHighlightSpan = (span: ByteSpan | { start: number; end: number; name?: string }) => {
    setHighlightSpan(span);
    setActiveTab('hex');
  };

  return (
    <div className="w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Hero / Input Section */}
      <div className="space-y-4">
        <div className="max-w-3xl">
          <h2 className="text-2xl sm:text-3xl font-bold tracking-tight text-white">
            Inspect Windows PE Executable Headers
          </h2>
          <p className="mt-1 text-sm text-slate-400">
            Fetch headers over HTTP using partial Range requests, parse DOS & COFF structures, verify exploit mitigations, and analyze sections with zero local installation.
          </p>
        </div>

        {/* URL Input Bar */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            fetchUrl(urlInput);
          }}
          className="flex flex-col sm:flex-row items-stretch gap-3"
        >
          <div className="relative flex-1">
            <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
              <Globe className="w-4 h-4" />
            </div>
            <input
              type="text"
              placeholder="Enter direct URL to .exe, .dll, or .sys binary (e.g. https://.../app.exe)"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              className="w-full pl-10 pr-4 py-3 bg-slate-900 border border-slate-800 rounded-xl text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500 transition-all font-mono"
            />
          </div>

          <div className="flex items-center gap-2">
            <button
              type="submit"
              disabled={loading || !urlInput.trim()}
              className="flex items-center justify-center gap-2 px-5 py-3 rounded-xl bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 disabled:pointer-events-none text-white text-sm font-semibold transition-colors shadow-lg shadow-indigo-600/20 whitespace-nowrap"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Fetching Header...</span>
                </>
              ) : (
                <>
                  <span>Fetch & Inspect</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>

            {/* Local File Upload Button */}
            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileUpload}
              accept=".exe,.dll,.sys,.scr,.ocx,.efi"
              className="hidden"
            />
            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              className="flex items-center justify-center gap-2 px-4 py-3 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 text-sm font-medium transition-colors whitespace-nowrap"
              title="Upload local .exe or .dll file"
            >
              <Upload className="w-4 h-4" />
              <span className="hidden sm:inline">Upload Binary</span>
            </button>
          </div>
        </form>

        {/* Quick Sample Presets */}
        <div className="flex flex-wrap items-center gap-2 pt-1 text-xs">
          <span className="text-slate-500 font-medium">Quick Presets:</span>
          {SAMPLE_BINARIES.map((sample) => (
            <button
              key={sample.id}
              onClick={() => loadSample(sample)}
              className="px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-slate-700 text-slate-300 transition-all font-sans"
            >
              {sample.name}
            </button>
          ))}
        </div>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="p-4 rounded-xl bg-rose-950/60 border border-rose-800/60 text-rose-200 text-xs flex items-start gap-3 shadow-lg">
          <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <span className="font-semibold">Inspection Failed</span>
            <p className="text-rose-300/90 leading-relaxed">{error}</p>
          </div>
        </div>
      )}

      {/* Main Analysis Workspace */}
      {parsedPe && parsedPe.isValidPE && (
        <div className="space-y-6">
          {/* Active Target Banner */}
          <div className="flex flex-wrap items-center justify-between gap-4 p-4 rounded-xl bg-slate-900/80 border border-slate-800 text-xs">
            <div className="flex items-center gap-3 min-w-0">
              <div className="p-2 rounded-lg bg-indigo-500/10 text-indigo-400">
                <FileCheck className="w-4 h-4" />
              </div>
              <div className="min-w-0">
                <div className="text-[11px] text-slate-400">Inspecting Target</div>
                <div className="text-slate-100 font-mono font-medium truncate max-w-xl">
                  {activeUrl}
                </div>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <span className="text-slate-400 font-mono tabular-nums">
                Buffer: {parsedPe.fileSize.toLocaleString()} bytes
              </span>
              <button
                onClick={() => setIsExportOpen(true)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-medium transition-colors"
              >
                <Code2 className="w-3.5 h-3.5" />
                <span>Export / C Structs</span>
              </button>
            </div>
          </div>

          {/* Navigation Tabs (Functional segmented controls) */}
          <div className="flex items-center gap-1 p-1 bg-slate-900/90 border border-slate-800 rounded-xl overflow-x-auto text-xs">
            <button
              onClick={() => setActiveTab('overview')}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg font-medium transition-colors whitespace-nowrap shrink-0 ${
                activeTab === 'overview'
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <FileCode className="w-4 h-4" />
              <span>Header Overview</span>
            </button>

            <button
              onClick={() => setActiveTab('hex')}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg font-medium transition-colors whitespace-nowrap shrink-0 ${
                activeTab === 'hex'
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Binary className="w-4 h-4" />
              <span>Hex Inspector</span>
            </button>

            <button
              onClick={() => setActiveTab('sections')}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg font-medium transition-colors whitespace-nowrap shrink-0 ${
                activeTab === 'sections'
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Layers className="w-4 h-4" />
              <span>Sections ({parsedPe.sections.length})</span>
            </button>

            <button
              onClick={() => setActiveTab('directories')}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg font-medium transition-colors whitespace-nowrap shrink-0 ${
                activeTab === 'directories'
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <FolderGit2 className="w-4 h-4" />
              <span>Data Directories (16)</span>
            </button>

            <button
              onClick={() => setActiveTab('exports')}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg font-medium transition-colors whitespace-nowrap shrink-0 ${
                activeTab === 'exports'
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : parsedPe.exportDirectory
                  ? 'text-teal-300 hover:text-white hover:bg-slate-800/60'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Share2 className="w-4 h-4" />
              <span>
                Export Table {parsedPe.exportDirectory ? `(${parsedPe.exportDirectory.functions.length})` : ''}
              </span>
              {parsedPe.exportDirectory && (
                <span className="w-1.5 h-1.5 rounded-full bg-teal-400" />
              )}
            </button>

            <button
              onClick={() => setActiveTab('security')}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg font-medium transition-colors whitespace-nowrap shrink-0 ${
                activeTab === 'security'
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Shield className="w-4 h-4" />
              <span>Exploit Mitigations</span>
            </button>

            <button
              onClick={() => setActiveTab('imports')}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg font-medium transition-colors whitespace-nowrap shrink-0 ${
                activeTab === 'imports'
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <FileCode className="w-4 h-4" />
              <span>Import Table {parsedPe.imports ? `(${parsedPe.imports.length})` : ''}</span>
            </button>

            <button
              onClick={() => setActiveTab('rich')}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg font-medium transition-colors whitespace-nowrap shrink-0 ${
                activeTab === 'rich'
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Binary className="w-4 h-4" />
              <span>Rich Header</span>
            </button>
          </div>

          {/* Active Tab View Body */}
          <div className="pt-2">
            {activeTab === 'overview' && (
              <PeOverviewCard pe={parsedPe} onHighlightSpan={handleHighlightSpan} />
            )}

            {activeTab === 'hex' && (
              <HexViewer
                data={parsedPe.data}
                spans={parsedPe.spans}
                highlightSpan={highlightSpan}
              />
            )}

            {activeTab === 'sections' && (
              <SectionsTable
                sections={parsedPe.sections}
                onSelectSection={handleSelectSection}
                selectedSectionIndex={selectedSectionIndex}
              />
            )}

            {activeTab === 'directories' && (
              <DataDirectoriesTable
                directories={parsedPe.optionalHeader?.dataDirectories || []}
                onSelectDirectory={handleSelectDirectory}
              />
            )}

            {activeTab === 'exports' && (
              <ExportsView
                exportDirectory={parsedPe.exportDirectory}
                onHighlightDirectory={() => {
                  if (parsedPe.exportDirectory) {
                    setHighlightSpan({
                      start: parsedPe.exportDirectory.directoryOffset,
                      end: parsedPe.exportDirectory.directoryOffset + 40,
                      name: `IMAGE_EXPORT_DIRECTORY (${parsedPe.exportDirectory.dllName})`,
                    });
                    setActiveTab('hex');
                  }
                }}
                onHighlightExport={(fn) => {
                  if (parsedPe.exportDirectory) {
                    setHighlightSpan({
                      start: parsedPe.exportDirectory.directoryOffset,
                      end: parsedPe.exportDirectory.directoryOffset + 40,
                      name: `Export: ${fn.name || `#${fn.ordinal}`}`,
                    });
                    setActiveTab('hex');
                  }
                }}
              />
            )}

            {activeTab === 'security' && (
              <SecurityChecklist security={parsedPe.security} />
            )}

            {activeTab === 'imports' && (
              <ImportsView imports={parsedPe.imports} />
            )}

            {activeTab === 'rich' && (
              <RichHeaderView richHeader={parsedPe.richHeader} />
            )}
          </div>
        </div>
      )}

      {/* Export Modal */}
      {isExportOpen && parsedPe && (
        <ExportModal
          pe={parsedPe}
          onClose={() => setIsExportOpen(false)}
          sourceUrl={activeUrl}
        />
      )}
    </div>
  );
};
