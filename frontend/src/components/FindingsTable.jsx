import React, { useState } from 'react';
import { Search, ChevronDown, ChevronUp, ExternalLink, ShieldAlert, CheckCircle2, Filter, Copy, Check, Terminal, BookOpen, AlertTriangle } from 'lucide-react';

export default function FindingsTable({ findings = [] }) {
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedId, setExpandedId] = useState(null);
  const [copiedId, setCopiedId] = useState(null);

  const toggleExpand = (id) => {
    setExpandedId(expandedId === id ? null : id);
  };

  const handleCopyEvidence = (id, data) => {
    navigator.clipboard.writeText(typeof data === 'string' ? data : JSON.stringify(data, null, 2));
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const filteredFindings = findings.filter((f) => {
    const matchesSev = filterSeverity === 'ALL' || f.severity?.toUpperCase() === filterSeverity;
    const q = searchQuery.toLowerCase();
    const matchesSearch =
      !q ||
      f.title?.toLowerCase().includes(q) ||
      f.rule_id?.toLowerCase().includes(q) ||
      f.rfc_reference?.toLowerCase().includes(q) ||
      f.category?.toLowerCase().includes(q);
    return matchesSev && matchesSearch;
  });

  const getSeverityBadge = (sev) => {
    const s = (sev || 'MEDIUM').toUpperCase();
    switch (s) {
      case 'CRITICAL':
        return 'bg-rose-50 text-rose-800 border-rose-200';
      case 'HIGH':
        return 'bg-orange-50 text-orange-800 border-orange-200';
      case 'MEDIUM':
        return 'bg-amber-50 text-amber-800 border-amber-200';
      case 'LOW':
        return 'bg-blue-50 text-blue-800 border-blue-200';
      default:
        return 'bg-emerald-50 text-emerald-800 border-emerald-200';
    }
  };

  const getRfcUrl = (rfcRef) => {
    if (!rfcRef) return 'https://datatracker.ietf.org/doc/html/rfc8247';
    const match = rfcRef.match(/RFC\s*(\d+)/i);
    return match ? `https://datatracker.ietf.org/doc/html/rfc${match[1]}` : 'https://datatracker.ietf.org';
  };

  const counts = {
    ALL: findings.length,
    CRITICAL: findings.filter((f) => f.severity === 'CRITICAL').length,
    HIGH: findings.filter((f) => f.severity === 'HIGH').length,
    MEDIUM: findings.filter((f) => f.severity === 'MEDIUM').length,
    LOW: findings.filter((f) => f.severity === 'LOW').length,
  };

  return (
    <div className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
      
      {/* Header & Filter Bar */}
      <div className="px-5 py-4 border-b border-slate-200/80 bg-slate-50/50 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-800 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-indigo-600" />
              <span>Vulnerability Findings & RFC Non-Conformances</span>
            </h3>
            <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-slate-200 text-slate-700">
              {filteredFindings.length} Total
            </span>
          </div>
          <p className="text-[11px] text-slate-500 mt-0.5">
            Real-time IKEv1/IKEv2 proposal audit mapped against IETF cryptographic standards
          </p>
        </div>

        {/* Search Input */}
        <div className="relative w-full md:w-72">
          <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            placeholder="Filter by rule, cipher, RFC..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-8 pr-10 py-1.5 text-xs font-mono bg-white border border-slate-200 rounded-lg focus:outline-none focus:ring-1 focus:ring-indigo-500 focus:border-indigo-500 transition-all placeholder:text-slate-400"
          />
          <span className="absolute right-2 top-1/2 -translate-y-1/2">
            <kbd className="text-[9px]">⌘F</kbd>
          </span>
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="px-5 py-2.5 border-b border-slate-100 flex items-center gap-1.5 overflow-x-auto text-xs bg-white">
        <span className="text-[11px] font-mono text-slate-400 mr-1 shrink-0">Severity:</span>
        {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
          <button
            key={sev}
            onClick={() => setFilterSeverity(sev)}
            className={`px-2.5 py-1 rounded-md text-[11px] font-mono transition-all shrink-0 cursor-pointer ${
              filterSeverity === sev
                ? 'bg-slate-900 text-white font-semibold shadow-2xs'
                : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
            }`}
          >
            {sev} ({counts[sev] || 0})
          </button>
        ))}
      </div>

      {/* Findings Table Rows */}
      <div className="divide-y divide-slate-100">
        {filteredFindings.length === 0 ? (
          <div className="p-10 text-center text-slate-400 text-xs flex flex-col items-center justify-center">
            <CheckCircle2 className="w-8 h-8 text-emerald-500 mb-2" />
            <span className="font-semibold text-slate-700">No matching non-conformances found</span>
            <span className="text-[11px] mt-0.5">The current filter criteria returned zero detected vulnerabilities.</span>
          </div>
        ) : (
          filteredFindings.map((f) => {
            const isExpanded = expandedId === f.id;
            let evidenceObj = null;
            if (f.evidence_json) {
              try {
                evidenceObj = typeof f.evidence_json === 'string' ? JSON.parse(f.evidence_json) : f.evidence_json;
              } catch (e) {
                evidenceObj = f.evidence_json;
              }
            }

            return (
              <div key={f.id} className="transition-colors hover:bg-slate-50/60">
                <div
                  onClick={() => toggleExpand(f.id)}
                  className="flex items-center justify-between p-3.5 sm:px-5 cursor-pointer select-none"
                >
                  <div className="flex items-center gap-3 min-w-0 pr-4">
                    <span className={`px-2 py-0.5 text-[10px] font-mono font-bold rounded border shrink-0 ${getSeverityBadge(f.severity)}`}>
                      {f.severity}
                    </span>
                    <span className="text-[11px] font-mono font-medium text-slate-500 shrink-0 hidden sm:inline">
                      {f.rule_id}
                    </span>
                    <span className="text-xs font-medium text-slate-900 truncate">
                      {f.title}
                    </span>
                  </div>

                  <div className="flex items-center gap-2.5 shrink-0">
                    {f.rfc_reference && (
                      <a
                        href={getRfcUrl(f.rfc_reference)}
                        target="_blank"
                        rel="noopener noreferrer"
                        onClick={(e) => e.stopPropagation()}
                        className="inline-flex items-center gap-1 text-[11px] font-mono font-medium text-indigo-600 bg-indigo-50/80 hover:bg-indigo-100 px-2 py-0.5 rounded border border-indigo-200/70 transition-colors"
                        title="View Official IETF RFC Specification"
                      >
                        <BookOpen className="w-3 h-3" />
                        <span>{f.rfc_reference}</span>
                        <ExternalLink className="w-2.5 h-2.5 opacity-60" />
                      </a>
                    )}
                    <span className="text-slate-400 p-1">
                      {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                    </span>
                  </div>
                </div>

                {/* Expanded Technical Drawer */}
                {isExpanded && (
                  <div className="px-5 pb-4 pt-1 bg-slate-50/70 border-t border-slate-100 text-xs space-y-3">
                    
                    {/* Description & Impact */}
                    <div>
                      <span className="text-[11px] font-mono uppercase tracking-wider text-slate-500 font-semibold block mb-1">
                        Vulnerability Mechanism & Impact:
                      </span>
                      <p className="text-slate-700 leading-relaxed bg-white p-3 rounded-lg border border-slate-200/80 text-[11px]">
                        {f.description}
                      </p>
                    </div>

                    {/* Actionable Remediation */}
                    {f.remediation_hint && (
                      <div className="p-3 bg-emerald-50/80 border border-emerald-200/90 rounded-lg text-emerald-900">
                        <span className="text-[11px] font-mono font-bold flex items-center gap-1.5 text-emerald-950 mb-1">
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                          Recommended RFC 8247 Remediation:
                        </span>
                        <p className="text-[11px] text-emerald-800 font-mono">
                          {f.remediation_hint}
                        </p>
                      </div>
                    )}

                    {/* Offending Evidence JSON */}
                    {evidenceObj && (
                      <div>
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-[11px] font-mono uppercase tracking-wider text-slate-500 font-semibold">
                            Offending Parameters (Extracted Evidence):
                          </span>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleCopyEvidence(f.id, evidenceObj);
                            }}
                            className="inline-flex items-center gap-1 text-[10px] font-mono text-slate-600 hover:text-slate-900 cursor-pointer"
                          >
                            {copiedId === f.id ? (
                              <Check className="w-3 h-3 text-emerald-600" />
                            ) : (
                              <Copy className="w-3 h-3 text-slate-400" />
                            )}
                            <span>{copiedId === f.id ? 'Copied' : 'Copy Evidence'}</span>
                          </button>
                        </div>
                        <pre className="p-2.5 bg-slate-900 text-slate-100 rounded-lg text-[10px] font-mono overflow-x-auto leading-relaxed">
                          {JSON.stringify(evidenceObj, null, 2)}
                        </pre>
                      </div>
                    )}

                    <div className="flex items-center gap-3 text-[10px] font-mono text-slate-400 pt-1 border-t border-slate-200/60">
                      <span>Category: {f.category}</span>
                      <span>•</span>
                      <span>Rule Ref: {f.rule_id}</span>
                      <span>•</span>
                      <span>Enforced RFC: {f.rfc_reference || 'RFC 8247'}</span>
                    </div>

                  </div>
                )}
              </div>
            );
          })
        )}
      </div>

    </div>
  );
}

