import React, { useState } from 'react';
import { Terminal, Copy, Check, Download, ShieldCheck, AlertOctagon, Code2, Play, ExternalLink } from 'lucide-react';

export default function RemediationDiff({ assessment }) {
  const [platform, setPlatform] = useState('swanctl');
  const [copied, setCopied] = useState(false);
  const [copiedVerify, setCopiedVerify] = useState(false);

  if (!assessment) return null;

  const beforeFull = assessment.config_diff_before || '';
  const afterFull = assessment.config_diff_after || '';

  let beforeSnippet = beforeFull;
  let afterSnippet = afterFull;

  if (beforeFull.includes('! --- Cisco')) {
    const partsBefore = beforeFull.split('! --- Cisco IOS Configuration ---');
    const partsAfter = afterFull.split('! +++ Cisco IOS Remediated +++');
    if (platform === 'swanctl') {
      beforeSnippet = partsBefore[0]?.trim() || '';
      afterSnippet = partsAfter[0]?.trim() || '';
    } else {
      beforeSnippet = '! --- Cisco IOS Configuration ---\n' + (partsBefore[1]?.trim() || '');
      afterSnippet = '! +++ Cisco IOS Remediated +++\n' + (partsAfter[1]?.trim() || '');
    }
  }

  const handleCopy = (text) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleCopyVerify = (text) => {
    navigator.clipboard.writeText(text);
    setCopiedVerify(true);
    setTimeout(() => setCopiedVerify(false), 2000);
  };

  const handleDownload = (text, filename) => {
    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(url);
  };

  const verificationCommands = {
    swanctl: 'sudo swanctl --load-conns && sudo swanctl --initiate --child net-traffic',
    cisco: 'show crypto ikev2 sa detail\nshow crypto ipsec sa',
  };

  const renderCodeWithLineNumbers = (code, type) => {
    const lines = code.split('\n');
    return (
      <div className="py-2 text-[11px] font-mono leading-relaxed select-text">
        {lines.map((line, idx) => {
          const isComment = line.trim().startsWith('#') || line.trim().startsWith('!');
          const isImportant = line.includes('proposals') || line.includes('version') || line.includes('encryption') || line.includes('group');
          
          let lineBg = '';
          if (type === 'before') {
            if (isImportant && (line.includes('3des') || line.includes('md5') || line.includes('1024') || line.includes('version = 1'))) {
              lineBg = 'bg-rose-500/10 text-rose-950 dark:text-rose-200 font-semibold';
            }
          } else {
            if (isImportant && (line.includes('aes256') || line.includes('modp2048') || line.includes('version = 2') || line.includes('group 19'))) {
              lineBg = 'bg-emerald-500/10 text-emerald-950 dark:text-emerald-200 font-semibold';
            }
          }

          return (
            <div key={idx} className={`flex px-3 hover:bg-slate-100/60 dark:hover:bg-slate-800/40 ${lineBg}`}>
              <span className="w-8 text-right pr-3 select-none text-slate-400 dark:text-slate-600 font-mono text-[10px]">
                {idx + 1}
              </span>
              <span className="w-4 text-center select-none text-slate-400 dark:text-slate-600 font-mono text-[10px]">
                {type === 'before' ? '-' : '+'}
              </span>
              <span className={`flex-1 whitespace-pre-wrap ${isComment ? 'text-slate-400 dark:text-slate-500 italic' : 'text-slate-800 dark:text-slate-200'}`}>
                {line}
              </span>
            </div>
          );
        })}
      </div>
    );
  };

  return (
    <div className="bg-white dark:bg-[#111827] rounded-[10px] border border-[#E2E8F0] dark:border-slate-800 shadow-2xs overflow-hidden transition-colors">
      
      {/* Header & Platform Switcher */}
      <div className="px-5 py-3.5 border-b border-[#E2E8F0] dark:border-slate-800 bg-[#F6F8FB]/80 dark:bg-[#0F172A]/70 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-[#4F46E5] dark:text-indigo-400" />
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-[#0F172A] dark:text-[#F8FAFC]">
              Actionable Configuration Remediation
            </h3>
          </div>
          <p className="text-[11px] text-[#64748B] dark:text-slate-400 mt-0.5">
            Side-by-side syntactic diff upgrading legacy tunnels to RFC 8247 & RFC 8221 compliance
          </p>
        </div>

        {/* Appliance Switcher */}
        <div className="flex items-center p-0.5 bg-slate-100 dark:bg-slate-800 rounded-[7px] border border-slate-200 dark:border-slate-700 text-xs font-mono">
          <button
            onClick={() => setPlatform('swanctl')}
            className={`px-3 py-1 text-[11px] font-semibold rounded-[5px] transition-all cursor-pointer ${
              platform === 'swanctl'
                ? 'bg-white dark:bg-slate-700 text-[#0F172A] dark:text-white shadow-2xs'
                : 'text-[#64748B] dark:text-slate-400 hover:text-[#0F172A] dark:hover:text-white'
            }`}
          >
            strongSwan (swanctl.conf)
          </button>
          <button
            onClick={() => setPlatform('cisco')}
            className={`px-3 py-1 text-[11px] font-semibold rounded-[5px] transition-all cursor-pointer ${
              platform === 'cisco'
                ? 'bg-white dark:bg-slate-700 text-[#0F172A] dark:text-white shadow-2xs'
                : 'text-[#64748B] dark:text-slate-400 hover:text-[#0F172A] dark:hover:text-white'
            }`}
          >
            Cisco IOS-XE (crypto ikev2)
          </button>
        </div>
      </div>

      {/* Side-by-Side Diff Panels */}
      <div className="grid grid-cols-1 lg:grid-cols-2 divide-y lg:divide-y-0 lg:divide-x divide-[#E2E8F0] dark:divide-slate-800 border-b border-[#E2E8F0] dark:border-slate-800">
        
        {/* Left: Insecure Config (Before) */}
        <div className="flex flex-col bg-white dark:bg-[#111827]">
          <div className="flex items-center justify-between px-4 py-2 bg-rose-50/70 dark:bg-rose-950/30 border-b border-rose-100 dark:border-rose-900/40">
            <div className="flex items-center gap-1.5 text-rose-800 dark:text-rose-300 text-[11px] font-mono font-bold">
              <AlertOctagon className="w-3.5 h-3.5 text-rose-600 dark:text-rose-400" />
              <span>DETECTED INSECURE CONFIGURATION</span>
            </div>
            <span className="text-[10px] font-mono text-rose-600 dark:text-rose-400 bg-rose-100 dark:bg-rose-950/60 px-1.5 py-0.2 rounded font-bold">
              NON-COMPLIANT
            </span>
          </div>

          <div className="overflow-x-auto max-h-[380px] overflow-y-auto bg-slate-50/30 dark:bg-[#0B0F19]/40">
            {renderCodeWithLineNumbers(beforeSnippet, 'before')}
          </div>
        </div>

        {/* Right: Remediated Config (After) */}
        <div className="flex flex-col bg-white dark:bg-[#111827]">
          <div className="flex items-center justify-between px-4 py-2 bg-emerald-50/70 dark:bg-emerald-950/30 border-b border-emerald-100 dark:border-emerald-900/40">
            <div className="flex items-center gap-1.5 text-emerald-800 dark:text-emerald-300 text-[11px] font-mono font-bold">
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
              <span>RFC 8247 HARDENED REMEDIATION</span>
            </div>
            
            <div className="flex items-center gap-2">
              <button
                onClick={() => handleCopy(afterSnippet)}
                className="inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-mono font-medium bg-white dark:bg-[#161E2E] text-slate-700 dark:text-slate-200 border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800 rounded shadow-2xs transition-colors cursor-pointer"
              >
                {copied ? <Check className="w-3 h-3 text-emerald-600 dark:text-emerald-400" /> : <Copy className="w-3 h-3 text-slate-400" />}
                <span>{copied ? 'Copied!' : 'Copy Code'}</span>
              </button>

              <button
                onClick={() => handleDownload(afterSnippet, platform === 'swanctl' ? 'swanctl.conf' : 'cisco_vpn_hardened.cfg')}
                className="inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-mono font-medium bg-emerald-700 hover:bg-emerald-800 text-white rounded shadow-2xs transition-colors cursor-pointer"
              >
                <Download className="w-3 h-3" />
                <span>Save File</span>
              </button>
            </div>
          </div>

          <div className="overflow-x-auto max-h-[380px] overflow-y-auto bg-slate-50/30 dark:bg-[#0B0F19]/40">
            {renderCodeWithLineNumbers(afterSnippet, 'after')}
          </div>
        </div>

      </div>

      {/* Bottom Verification Command Strip */}
      <div className="px-5 py-3 bg-[#0F172A] text-slate-300 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono">
        <div className="flex items-center gap-2 min-w-0">
          <span className="text-emerald-400 font-bold flex items-center gap-1 shrink-0">
            <Play className="w-3 h-3" /> Test & Apply:
          </span>
          <code className="text-slate-200 truncate bg-slate-800/80 px-2 py-0.5 rounded text-[11px]">
            {verificationCommands[platform]}
          </code>
        </div>

        <button
          onClick={() => handleCopyVerify(verificationCommands[platform])}
          className="inline-flex items-center gap-1 px-2.5 py-1 text-[10px] font-mono text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded border border-slate-700 transition-colors cursor-pointer self-start sm:self-auto shrink-0"
        >
          {copiedVerify ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3 text-slate-400" />}
          <span>{copiedVerify ? 'Copied Command' : 'Copy CLI Command'}</span>
        </button>
      </div>

    </div>
  );
}
