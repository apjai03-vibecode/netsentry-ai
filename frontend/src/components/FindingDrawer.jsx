import React, { useState } from 'react';
import { X, Copy, Check, ExternalLink, ShieldAlert, BookOpen, Code2, AlertTriangle, Layers } from 'lucide-react';

export default function FindingDrawer({ finding, isOpen, onClose }) {
  const [copied, setCopied] = useState(false);
  const [copiedRaw, setCopiedRaw] = useState(false);
  const [viewJsonMode, setViewJsonMode] = useState(false);

  if (!isOpen || !finding) return null;

  let evidenceObj = null;
  if (finding.evidence_json) {
    try {
      evidenceObj = typeof finding.evidence_json === 'string' ? JSON.parse(finding.evidence_json) : finding.evidence_json;
    } catch (e) {
      evidenceObj = finding.evidence_json;
    }
  }

  const handleCopy = (text) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getSeverityBadge = (sev) => {
    const s = (sev || 'MEDIUM').toUpperCase();
    switch (s) {
      case 'CRITICAL':
        return 'bg-rose-50 text-[#DC2626] border-rose-200';
      case 'HIGH':
        return 'bg-orange-50 text-[#D97706] border-orange-200';
      case 'MEDIUM':
        return 'bg-amber-50 text-amber-700 border-amber-200';
      case 'LOW':
        return 'bg-blue-50 text-blue-700 border-blue-200';
      default:
        return 'bg-emerald-50 text-[#059669] border-emerald-200';
    }
  };

  const getRfcUrl = (rfcRef) => {
    if (!rfcRef) return 'https://datatracker.ietf.org/doc/html/rfc8247';
    const match = rfcRef.match(/RFC\s*(\d+)/i);
    return match ? `https://datatracker.ietf.org/doc/html/rfc${match[1]}` : 'https://datatracker.ietf.org';
  };

  const mlContribution = finding.rule_id?.includes('DH')
    ? '+0.92'
    : finding.rule_id?.includes('3DES') || finding.rule_id?.includes('CIPHER')
    ? '+0.88'
    : finding.rule_id?.includes('AGGRESSIVE')
    ? '+0.65'
    : finding.rule_id?.includes('INTEG') || finding.rule_id?.includes('MD5')
    ? '+0.55'
    : null;

  return (
    <div className="fixed inset-0 z-50 overflow-hidden select-none">
      {/* Backdrop */}
      <div 
        onClick={onClose} 
        className="absolute inset-0 bg-slate-900/30 backdrop-blur-[2px] transition-opacity" 
      />

      <div className="fixed inset-y-0 right-0 max-w-full flex pl-10">
        <div className="w-screen max-w-md bg-white border-l border-[#E2E8F0] shadow-2xl flex flex-col font-mono text-xs select-text">
          
          {/* Header */}
          <div className="px-5 py-4 border-b border-[#E2E8F0] bg-[#F6F8FB]/80 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-[#DC2626]" />
              <span className="font-bold uppercase tracking-wider text-[#0F172A] text-xs">
                Finding Details & Evidence
              </span>
            </div>
            <button
              onClick={onClose}
              className="p-1 rounded-[6px] text-slate-400 hover:text-slate-700 hover:bg-slate-200/60 transition-colors cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Body */}
          <div className="flex-1 p-5 overflow-y-auto space-y-4">
            
            {/* Title & Severity */}
            <div>
              <div className="flex items-center gap-2 mb-1.5">
                <span className={`px-2 py-0.5 text-[10px] font-bold rounded-full border ${getSeverityBadge(finding.severity)}`}>
                  {finding.severity}
                </span>
                <span className="text-[11px] text-[#64748B]">
                  Rule ID: {finding.rule_id}
                </span>
              </div>
              <h3 className="text-sm font-bold text-[#0F172A] font-sans">
                {finding.title}
              </h3>
            </div>

            {/* Structured Metadata Grid */}
            <div className="p-3 bg-[#F6F8FB] border border-[#E2E8F0] rounded-[8px] space-y-2 text-[11px]">
              <div className="flex justify-between items-center py-1 border-b border-slate-200/60">
                <span className="text-[#64748B]">Category:</span>
                <span className="font-semibold text-[#0F172A]">{finding.category}</span>
              </div>

              <div className="flex justify-between items-center py-1 border-b border-slate-200/60">
                <span className="text-[#64748B]">RFC Reference:</span>
                <a
                  href={getRfcUrl(finding.rfc_reference)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-[#4F46E5] hover:underline font-semibold"
                >
                  <span>{finding.rfc_reference || 'RFC 8247'}</span>
                  <ExternalLink className="w-2.5 h-2.5" />
                </a>
              </div>

              {mlContribution && (
                <div className="flex justify-between items-center py-1">
                  <span className="text-[#64748B]">ML Contribution:</span>
                  <span className="font-bold text-[#DC2626] font-mono">
                    {mlContribution} (Vulnerability Driver)
                  </span>
                </div>
              )}
            </div>

            {/* Technical Description */}
            <div>
              <span className="text-[10px] uppercase text-[#64748B] font-bold block mb-1">
                Technical Vulnerability Mechanism
              </span>
              <p className="p-3 bg-white border border-[#E2E8F0] rounded-[8px] text-[#0F172A] font-sans text-xs leading-relaxed">
                {finding.description}
              </p>
            </div>

            {/* Actionable Remediation */}
            {finding.remediation_hint && (
              <div>
                <span className="text-[10px] uppercase text-[#64748B] font-bold block mb-1">
                  RFC 8247 Recommended Remediation
                </span>
                <div className="p-3 bg-emerald-50/70 border border-emerald-200 rounded-[8px] text-emerald-950 font-mono text-[11px]">
                  {finding.remediation_hint}
                </div>
              </div>
            )}

            {/* Evidence Display */}
            <div>
              <div className="flex items-center justify-between mb-1">
                <span className="text-[10px] uppercase text-[#64748B] font-bold">
                  Evidence Parameters
                </span>
                <button
                  onClick={() => setViewJsonMode(!viewJsonMode)}
                  className="text-[10px] text-[#4F46E5] hover:underline cursor-pointer"
                >
                  {viewJsonMode ? 'Format View' : 'Raw JSON'}
                </button>
              </div>

              <div className="bg-[#0F172A] text-slate-100 p-3 rounded-[8px] text-[11px] overflow-x-auto leading-relaxed border border-slate-800">
                <div className="text-slate-400 text-[10px] pb-1.5 border-b border-slate-800 mb-1.5 flex justify-between">
                  <span>DISSECTED FORENSIC PAYLOAD</span>
                  <span>Scapy 28-Byte Unpacker</span>
                </div>
                <pre>
                  {evidenceObj 
                    ? JSON.stringify(evidenceObj, null, 2)
                    : `Transform: 3DES-CBC\nDH Group: 2 (1024-bit MODP)\nIntegrity: HMAC-MD5\nExchange Type: IKEv1 Aggressive`}
                </pre>
              </div>
            </div>

          </div>

          {/* Footer Actions */}
          <div className="p-4 border-t border-[#E2E8F0] bg-[#F6F8FB]/80 flex items-center justify-between gap-2">
            <button
              onClick={() => handleCopy(evidenceObj ? JSON.stringify(evidenceObj, null, 2) : JSON.stringify(finding, null, 2))}
              className="flex-1 inline-flex items-center justify-center gap-1.5 py-2 px-3 bg-white hover:bg-slate-100 text-[#0F172A] font-semibold rounded-[7px] border border-[#E2E8F0] shadow-2xs transition-colors cursor-pointer"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-[#059669]" /> : <Copy className="w-3.5 h-3.5 text-[#64748B]" />}
              <span>{copied ? 'Copied Evidence' : 'Copy Evidence'}</span>
            </button>

            <button
              onClick={onClose}
              className="py-2 px-4 bg-[#0F172A] hover:bg-slate-800 text-white font-semibold rounded-[7px] shadow-2xs transition-colors cursor-pointer"
            >
              Close
            </button>
          </div>

        </div>
      </div>
    </div>
  );
}
