/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { PeHeaderInspector } from './components/PeHeaderInspector';
import { Shield, ExternalLink, Binary } from 'lucide-react';

export default function App() {
  const [docModalOpen, setDocModalOpen] = useState(false);

  return (
    <div className="min-h-screen flex flex-col bg-slate-950 text-slate-100">
      {/* Top Bar Contract (3 Zones, gap-8) */}
      <header className="flex items-center justify-between gap-8 px-6 py-4 border-b border-slate-800 bg-slate-950 sticky top-0 z-40 backdrop-blur-md">
        {/* Zone 1: Single text element wordmark */}
        <div className="flex items-center gap-2.5 whitespace-nowrap shrink-0">
          <div className="p-1.5 rounded-lg bg-indigo-600 text-white">
            <Binary className="w-5 h-5" />
          </div>
          <span className="text-lg font-bold tracking-tight text-white font-sans">
            PE Header Inspector
          </span>
        </div>

        {/* Zone 2: Concise single-line text navigation links */}
        <nav className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-400">
          <a
            href="#inspector"
            className="text-slate-200 hover:text-white transition-colors whitespace-nowrap shrink-0"
          >
            PE Inspector
          </a>
          <button
            onClick={() => setDocModalOpen(true)}
            className="hover:text-white transition-colors whitespace-nowrap shrink-0 text-left"
          >
            COFF & PE Specification
          </button>
          <a
            href="https://learn.microsoft.com/en-us/windows/win32/debug/pe-format"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-white transition-colors whitespace-nowrap shrink-0 flex items-center gap-1"
          >
            <span>Microsoft Docs</span>
            <ExternalLink className="w-3 h-3 text-slate-500" />
          </a>
        </nav>

        {/* Zone 3: 1 primary action */}
        <div className="flex items-center gap-3 shrink-0">
          <button
            onClick={() => {
              const input = document.querySelector('input[type="text"]') as HTMLInputElement;
              if (input) {
                input.focus();
                input.scrollIntoView({ behavior: 'smooth' });
              }
            }}
            className="px-4 py-2 text-xs font-semibold text-white bg-indigo-600 rounded-lg hover:bg-indigo-500 transition-colors whitespace-nowrap shrink-0 shadow-sm"
          >
            Enter Executable URL
          </button>
        </div>
      </header>

      {/* Main Content Viewport */}
      <main id="inspector" className="flex-1">
        <PeHeaderInspector />
      </main>

      {/* PE Spec Reference Modal */}
      {docModalOpen && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-2xl p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h3 className="text-base font-semibold text-white">Windows PE/COFF Format Reference</h3>
              <button
                onClick={() => setDocModalOpen(false)}
                className="text-slate-400 hover:text-white text-sm"
              >
                Close
              </button>
            </div>

            <div className="space-y-3 text-xs text-slate-300 leading-relaxed max-h-[60vh] overflow-y-auto pr-2">
              <p>
                The Portable Executable (PE) format is an encapsulation of the Common Object File Format (COFF)
                used by 32-bit and 64-bit versions of Windows operating systems for executable files (.exe), object code,
                dynamic-link libraries (.dll), and device drivers (.sys).
              </p>

              <div className="space-y-1.5 pt-2">
                <div className="font-semibold text-indigo-400">1. MS-DOS Header (IMAGE_DOS_HEADER)</div>
                <p className="text-slate-400">
                  Starts with <code>0x5A4D</code> ('MZ'). Contains legacy 16-bit register values and the crucial field{' '}
                  <code>e_lfanew</code> at offset 0x3C, pointing to the PE signature.
                </p>
              </div>

              <div className="space-y-1.5 pt-2">
                <div className="font-semibold text-indigo-400">2. PE Signature & COFF File Header</div>
                <p className="text-slate-400">
                  Four bytes <code>PE\0\0</code> (0x00004550) followed by 20 bytes specifying the machine architecture
                  (AMD64 0x8664, i386 0x014C, ARM64 0xAA64), number of section headers, and compilation timestamp.
                </p>
              </div>

              <div className="space-y-1.5 pt-2">
                <div className="font-semibold text-indigo-400">3. Optional Header (PE32 / PE32+)</div>
                <p className="text-slate-400">
                  Required for executables. Defines the execution entry point (AddressOfEntryPoint), default virtual ImageBase,
                  alignment settings, OS subsystem (GUI vs Console), and 16 Data Directory entries.
                </p>
              </div>

              <div className="space-y-1.5 pt-2">
                <div className="font-semibold text-indigo-400">4. Section Headers (IMAGE_SECTION_HEADER)</div>
                <p className="text-slate-400">
                  Array of 40-byte descriptors mapping each named section (<code>.text</code> for code, <code>.rdata</code> for read-only data/imports, <code>.data</code> for global variables, <code>.rsrc</code> for resources).
                </p>
              </div>
            </div>

            <div className="pt-3 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setDocModalOpen(false)}
                className="px-4 py-2 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg transition-colors"
              >
                Dismiss
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Footer */}
      <footer className="border-t border-slate-850 bg-slate-950 py-6 px-6 text-xs text-slate-500 flex flex-col sm:flex-row items-center justify-between gap-4">
        <div>
          Portable Executable (PE) & COFF Binary Header Inspection Utility
        </div>
        <div className="flex items-center gap-4 text-slate-400">
          <span>Compliant with Microsoft PE/COFF Spec v8.3+</span>
          <span aria-hidden="true">·</span>
          <span>HTTP Range Byte Fetching</span>
        </div>
      </footer>
    </div>
  );
}
