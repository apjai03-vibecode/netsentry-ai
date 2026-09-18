import React, { useState } from 'react';
import { Terminal, Copy, Check, Download, ShieldCheck, AlertOctagon } from 'lucide-react';

export default function RemediationDiff({ assessment }) {
  const [platform, setPlatform] = useState('swanctl');
  const [copied, setCopied] = useState(false);

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

  const handleDownload = (text, filename) => {
    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-4 border-b border-slate-100">
        <div>
          <h3 className="text-base font-bold text-slate-900 flex items-center gap-2">
            <Terminal className="w-5 h-5 text-indigo-600" />
            <span>Actionable Remediation: Before vs. After Configuration</span>
          </h3>
          <p className="text-xs text-slate-500 mt-0.5">
            Production-tested configuration snippets upgrading legacy handshakes to RFC 8247 & RFC 8221 standards.
          </p>
        </div>

        <div className="flex items-center gap-1.5 p-1 bg-slate-100 rounded-xl">
          <button
            onClick={() => setPlatform('swanctl')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-all cursor-pointer ${
              platform === 'swanctl'
                ? 'bg-white text-indigo-700 shadow-2xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            strongSwan (swanctl.conf)
          </button>
          <button
            onClick={() => setPlatform('cisco')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-all cursor-pointer ${
              platform === 'cisco'
                ? 'bg-white text-indigo-700 shadow-2xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Cisco IOS (crypto ikev2)
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mt-4">
        
        {/* Before Panel (Insecure) */}
        <div className="flex flex-col rounded-xl border border-rose-200 bg-rose-50/20 overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2.5 bg-rose-50 border-b border-rose-200/80">
            <div className="flex items-center gap-2">
              <AlertOctagon className="w-4 h-4 text-rose-600" />
              <span className="text-xs font-bold text-rose-800 uppercase tracking-wide">
                Before (Detected Insecure Config)
              </span>
            </div>
            <span className="text-[10px] text-rose-600 font-mono">vulnerable</span>
          </div>

          <pre className="p-4 text-xs font-mono text-slate-800 overflow-x-auto leading-relaxed max-h-96">
            {beforeSnippet}
          </pre>
        </div>

        {/* After Panel (Hardened) */}
        <div className="flex flex-col rounded-xl border border-emerald-200 bg-emerald-50/20 overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2.5 bg-emerald-50 border-b border-emerald-200/80">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-600" />
              <span className="text-xs font-bold text-emerald-800 uppercase tracking-wide">
                After (RFC 8247 Hardened Remediation)
              </span>
            </div>
            
            <div className="flex items-center gap-2">
              <button
                onClick={() => handleCopy(afterSnippet)}
                className="inline-flex items-center gap-1 px-2.5 py-1 text-[11px] font-medium bg-white text-slate-700 border border-emerald-200 hover:bg-emerald-100 rounded-lg shadow-2xs transition-colors cursor-pointer"
              >
                {copied ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3 text-slate-500" />}
                <span>{copied ? 'Copied!' : 'Copy'}</span>
              </button>

              <button
                onClick={() => handleDownload(afterSnippet, platform === 'swanctl' ? 'swanctl.conf' : 'cisco_vpn_hardened.cfg')}
                className="inline-flex items-center gap-1 px-2.5 py-1 text-[11px] font-medium bg-emerald-600 hover:bg-emerald-700 text-white rounded-lg shadow-2xs transition-colors cursor-pointer"
              >
                <Download className="w-3 h-3" />
                <span className="hidden sm:inline">Download</span>
              </button>
            </div>
          </div>

          <pre className="p-4 text-xs font-mono text-slate-800 overflow-x-auto leading-relaxed max-h-96">
            {afterSnippet}
          </pre>
        </div>

      </div>
    </div>
  );
}
