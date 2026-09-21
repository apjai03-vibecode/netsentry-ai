import React, { useState } from 'react';
import { ShieldAlert, Search, ExternalLink, ChevronRight, CheckCircle2, BookOpen } from 'lucide-react';

export default function SecurityFindings({ findings = [], onSelectFinding }) {
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');

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
        return 'bg-rose-50 dark:bg-rose-950/40 text-[#DC2626] dark:text-rose-400 border-rose-200 dark:border-rose-900/50';
      case 'HIGH':
        return 'bg-orange-50 dark:bg-amber-950/40 text-[#D97706] dark:text-amber-400 border-orange-200 dark:border-amber-900/50';
      case 'MEDIUM':
        return 'bg-amber-50 dark:bg-amber-950/30 text-amber-700 dark:text-amber-300 border-amber-200 dark:border-amber-800/40';
      case 'LOW':
        return 'bg-blue-50 dark:bg-blue-950/30 text-blue-700 dark:text-blue-300 border-blue-200 dark:border-blue-800/40';
      default:
        return 'bg-emerald-50 dark:bg-emerald-950/40 text-[#059669] dark:text-emerald-400 border-emerald-200 dark:border-emerald-900/50';
    }
  };

  const getMlContribution = (finding) => {
    if (finding.rule_id?.includes('DH') || finding.title?.includes('Diffie-Hellman')) {
      return '+0.92';
    }
    if (finding.rule_id?.includes('3DES') || finding.rule_id?.includes('CIPHER') || finding.title?.includes('3DES')) {
      return '+0.88';
    }
    if (finding.rule_id?.includes('AGGRESSIVE') || finding.title?.includes('Aggressive')) {
      return '+0.65';
    }
    if (finding.rule_id?.includes('INTEG') || finding.rule_id?.includes('MD5') || finding.title?.includes('MD5')) {
      return '+0.55';
    }
    return null;
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
    <section className="bg-white dark:bg-[#111827] rounded-[10px] border border-[#E2E8F0] dark:border-slate-800 shadow-2xs overflow-hidden transition-colors">
      
      {/* Header Bar */}
      <div className="px-5 py-3.5 border-b border-[#E2E8F0] dark:border-slate-800 bg-[#F6F8FB]/80 dark:bg-[#0F172A]/70 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <ShieldAlert className="w-4 h-4 text-[#DC2626] dark:text-rose-400" />
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-[#0F172A] dark:text-[#F8FAFC]">
                Security Findings
              </h2>
              <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded-full bg-rose-50 dark:bg-rose-950/40 text-[#DC2626] dark:text-rose-400 border border-rose-200 dark:border-rose-900/50">
                {findings.length} violations
              </span>
            </div>
            <p className="text-[11px] text-[#64748B] dark:text-slate-400 font-mono">
              Deterministic RFC 8247 non-conformance rules and extracted session vulnerabilities
            </p>
          </div>
        </div>

        {/* Search Input */}
        <div className="relative w-full md:w-64">
          <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400 dark:text-slate-500" />
          <input
            type="text"
            placeholder="Filter by rule, cipher, RFC..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-8 pr-10 py-1.5 text-xs font-mono bg-white dark:bg-[#161E2E] text-[#0F172A] dark:text-white border border-[#E2E8F0] dark:border-slate-700 rounded-[7px] focus:outline-none focus:ring-1 focus:ring-[#4F46E5] focus:border-[#4F46E5] placeholder:text-slate-400 dark:placeholder:text-slate-500 transition-all"
          />
          <span className="absolute right-2 top-1/2 -translate-y-1/2">
            <kbd className="text-[9px] font-mono text-slate-400 dark:text-slate-400 bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 px-1 py-0.5 rounded">⌘F</kbd>
          </span>
        </div>
      </div>

      {/* Filter Severity Tabs */}
      <div className="px-5 py-2 border-b border-[#E2E8F0] dark:border-slate-800 flex items-center gap-1.5 overflow-x-auto text-xs bg-white dark:bg-[#111827]">
        <span className="text-[10px] font-mono uppercase text-[#64748B] dark:text-slate-400 mr-1.5 shrink-0 font-semibold">Severity:</span>
        {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
          <button
            key={sev}
            onClick={() => setFilterSeverity(sev)}
            className={`px-2.5 py-1 rounded-[6px] text-[11px] font-mono transition-all shrink-0 cursor-pointer ${
              filterSeverity === sev
                ? 'bg-[#0F172A] dark:bg-slate-700 text-white font-semibold shadow-2xs'
                : 'bg-slate-100 dark:bg-slate-800 text-[#64748B] dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-700 hover:text-[#0F172A] dark:hover:text-white'
            }`}
          >
            {sev} ({counts[sev] || 0})
          </button>
        ))}
      </div>

      {/* Findings List */}
      <div className="divide-y divide-[#E2E8F0] dark:divide-slate-800">
        {filteredFindings.length === 0 ? (
          <div className="p-10 text-center text-[#64748B] dark:text-slate-400 text-xs flex flex-col items-center justify-center">
            <CheckCircle2 className="w-8 h-8 text-[#059669] dark:text-emerald-400 mb-2" />
            <span className="font-semibold text-[#0F172A] dark:text-white">No Matching Violations</span>
            <span className="text-[11px] mt-0.5">The current filter criteria returned zero detected cryptographic vulnerabilities.</span>
          </div>
        ) : (
          filteredFindings.map((f) => {
            const mlContrib = getMlContribution(f);

            return (
              <div
                key={f.id}
                onClick={() => onSelectFinding(f)}
                className="p-4 hover:bg-[#F6F8FB] dark:hover:bg-[#161E2E]/60 transition-colors cursor-pointer flex flex-col md:flex-row md:items-center justify-between gap-3 group"
              >
                {/* Left details */}
                <div className="space-y-1.5 min-w-0 flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={`px-2 py-0.5 text-[10px] font-mono font-bold rounded-full border ${getSeverityBadge(f.severity)}`}>
                      {f.severity}
                    </span>
                    <span className="text-xs font-mono font-semibold text-[#64748B] dark:text-slate-400">
                      {f.rule_id}
                    </span>
                    <span className="text-slate-300 dark:text-slate-600">•</span>
                    <span className="text-xs font-mono text-slate-500 dark:text-slate-400">
                      {f.category}
                    </span>
                  </div>

                  <h3 className="text-sm font-bold text-[#0F172A] dark:text-white group-hover:text-[#4F46E5] dark:group-hover:text-indigo-400 transition-colors">
                    {f.title}
                  </h3>

                  <p className="text-xs text-[#64748B] dark:text-slate-400 line-clamp-2 leading-relaxed">
                    {f.description}
                  </p>
                </div>

                {/* Right badges & inspect action */}
                <div className="flex items-center gap-3 shrink-0 self-start md:self-center">
                  {/* ML Contribution Badge */}
                  {mlContrib && (
                    <div className="inline-flex items-center gap-1 px-2.5 py-1 rounded-[6px] text-[11px] font-mono font-bold bg-rose-50 dark:bg-rose-950/40 text-[#DC2626] dark:text-rose-400 border border-rose-200 dark:border-rose-900/50">
                      <span>ML contribution {mlContrib}</span>
                    </div>
                  )}

                  {/* RFC Tag */}
                  {f.rfc_reference && (
                    <a
                      href={getRfcUrl(f.rfc_reference)}
                      target="_blank"
                      rel="noopener noreferrer"
                      onClick={(e) => e.stopPropagation()}
                      className="inline-flex items-center gap-1 text-[11px] font-mono text-[#4F46E5] dark:text-indigo-400 bg-indigo-50/70 dark:bg-indigo-950/40 hover:bg-indigo-100/90 dark:hover:bg-indigo-900/60 px-2 py-1 rounded-[6px] border border-indigo-200/80 dark:border-indigo-800/60 transition-colors"
                      title="View Official IETF RFC Specification"
                    >
                      <BookOpen className="w-3 h-3" />
                      <span>{f.rfc_reference}</span>
                      <ExternalLink className="w-2.5 h-2.5 opacity-60" />
                    </a>
                  )}

                  {/* Chevron Right */}
                  <div className="text-slate-400 dark:text-slate-500 group-hover:text-[#0F172A] dark:group-hover:text-white p-1 transition-colors">
                    <ChevronRight className="w-5 h-5 group-hover:translate-x-0.5 transition-transform" />
                  </div>
                </div>

              </div>
            );
          })
        )}
      </div>

    </section>
  );
}
