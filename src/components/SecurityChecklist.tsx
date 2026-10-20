import React from 'react';
import { SecurityAnalysis } from '../lib/pe-parser';
import { ShieldCheck, ShieldAlert, CheckCircle2, XCircle, Info, Lock, Cpu } from 'lucide-react';

interface SecurityChecklistProps {
  security: SecurityAnalysis;
}

export const SecurityChecklist: React.FC<SecurityChecklistProps> = ({ security }) => {
  const mitigations = [
    {
      name: 'ASLR (Dynamic Base)',
      enabled: security.aslr,
      flag: 'IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (0x0040)',
      description: 'Randomizes module base address at launch to prevent return-oriented programming (ROP) exploits.',
      impact: security.aslr ? 'Addresses randomized on every execution' : 'Loaded at fixed image base address',
    },
    {
      name: 'High Entropy VA',
      enabled: security.highEntropyVa,
      flag: 'IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA (0x0020)',
      description: 'Utilizes the complete 64-bit address space for address randomization, rendering brute-force guessing unfeasible.',
      impact: security.highEntropyVa ? 'Full 64-bit entropy enabled' : 'Limited entropy range or 32-bit binary',
    },
    {
      name: 'DEP / NX Compat',
      enabled: security.dep,
      flag: 'IMAGE_DLLCHARACTERISTICS_NX_COMPAT (0x0100)',
      description: 'Data Execution Prevention prevents execution of arbitrary shellcode residing on stack or heap pages.',
      impact: security.dep ? 'W^X (Write XOR Execute) memory enforced' : 'Data pages may be executable',
    },
    {
      name: 'Control Flow Guard (CFG)',
      enabled: security.cfg,
      flag: 'IMAGE_DLLCHARACTERISTICS_GUARD_CF (0x4000)',
      description: 'Performs compile-time security checks on indirect function call targets to thwart control flow hijacking.',
      impact: security.cfg ? 'Indirect call targets validated via bitmap' : 'No CFG compiler instrumentation detected',
    },
    {
      name: 'Authenticode Signature',
      enabled: security.authenticode,
      flag: 'IMAGE_DIRECTORY_ENTRY_SECURITY',
      description: 'Cryptographic signature verifying publisher identity and ensuring the binary has not been tampered with.',
      impact: security.authenticode
        ? `Signed certificate present (${(security.certSize / 1024).toFixed(1)} KB)`
        : 'Unsigned executable binary',
    },
    {
      name: 'SEH / SafeSEH',
      enabled: security.noSeh || security.safeSeh,
      flag: security.noSeh ? 'IMAGE_DLLCHARACTERISTICS_NO_SEH' : 'SafeSEH Handler Table',
      description: security.noSeh
        ? 'Binary does not use Structured Exception Handling (eliminates SEH overwrite attacks).'
        : 'Protected exception handler dispatch table.',
      impact: security.noSeh ? 'No SEH handlers utilized' : 'Exception handlers registered',
    },
    {
      name: '.NET CLR Metadata',
      enabled: security.isDotNet,
      flag: 'IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR',
      description: 'Managed code executing inside the Common Language Runtime with memory safety and type verification.',
      impact: security.isDotNet ? 'Managed .NET IL Application' : 'Native Unmanaged C/C++ Code',
    },
  ];

  const scoreBadgeColors = {
    High: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
    Medium: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
    Low: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
  };

  return (
    <div className="space-y-6">
      {/* Header score card */}
      <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-indigo-400">
            <Lock className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-base font-semibold text-slate-100">Exploit Mitigations & Hardening Audit</h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Evaluation of Windows OS defensive compiler flags and binary signature protections
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3 self-end md:self-auto">
          <div className="text-right">
            <div className="text-xs text-slate-400">Defense Posture</div>
            <div className="text-xs text-slate-500 mt-0.5">{security.arch} · {security.subsystem}</div>
          </div>
          <div
            className={`px-3 py-1.5 rounded-lg border text-sm font-semibold flex items-center gap-1.5 ${
              scoreBadgeColors[security.overallScore]
            }`}
          >
            {security.overallScore === 'High' ? (
              <ShieldCheck className="w-4 h-4" />
            ) : (
              <ShieldAlert className="w-4 h-4" />
            )}
            <span>{security.overallScore} Protection</span>
          </div>
        </div>
      </div>

      {/* Grid of Mitigations */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {mitigations.map((item) => (
          <div
            key={item.name}
            className={`p-4 rounded-xl border transition-all ${
              item.enabled
                ? 'bg-slate-900/90 border-slate-800 hover:border-slate-700'
                : 'bg-slate-900/50 border-slate-850 hover:border-slate-800'
            }`}
          >
            <div className="flex items-start justify-between gap-2">
              <div className="font-medium text-sm text-slate-200">{item.name}</div>
              {item.enabled ? (
                <div className="flex items-center gap-1 text-emerald-400 text-xs font-medium shrink-0">
                  <CheckCircle2 className="w-4 h-4" />
                  <span>Enabled</span>
                </div>
              ) : (
                <div className="flex items-center gap-1 text-slate-500 text-xs font-medium shrink-0">
                  <XCircle className="w-4 h-4 text-slate-600" />
                  <span>Disabled</span>
                </div>
              )}
            </div>

            <p className="text-xs text-slate-400 mt-2 leading-relaxed">{item.description}</p>

            <div className="mt-3 pt-3 border-t border-slate-800/80 text-[11px] font-mono text-slate-500 flex items-center justify-between">
              <span className="truncate max-w-[200px]" title={item.flag}>
                {item.flag}
              </span>
              <span className={`font-sans font-medium ${item.enabled ? 'text-indigo-400' : 'text-slate-500'}`}>
                {item.impact}
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* Analysis Notes */}
      {security.notes.length > 0 && (
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 text-xs text-slate-300">
          <div className="flex items-center gap-1.5 font-semibold text-slate-200 mb-2">
            <Info className="w-4 h-4 text-indigo-400" />
            <span>Security Assessment Findings</span>
          </div>
          <ul className="space-y-1 text-slate-400 list-disc list-inside">
            {security.notes.map((note, idx) => (
              <li key={idx} className="leading-relaxed">
                {note}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};
