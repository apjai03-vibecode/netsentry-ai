import React, { useState } from 'react';
import { Search, ChevronDown, ChevronUp, ExternalLink, ShieldAlert, CheckCircle2, Filter } from 'lucide-react';

export default function FindingsTable({ findings = [] }) {
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedId, setExpandedId] = useState(null);

  const toggleExpand = (id) => {
    setExpandedId(expandedId === id ? null : id);
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
        return 'bg-rose-50 text-rose-700 border-rose-200';
      case 'HIGH':
        return 'bg-orange-50 text-orange-700 border-orange-200';
      case 'MEDIUM':
        return 'bg-amber-50 text-amber-700 border-amber-200';
      case 'LOW':
        return 'bg-blue-50 text-blue-700 border-blue-200';
      default:
        return 'bg-emerald-50 text-emerald-700 border-emerald-200';
    }
  };

  return (
    <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-4 border-b border-slate-100">
        <div>
          <h3 className="text-base font-bold text-slate-900 flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-indigo-600" />
            <span>Security Findings & RFC Non-Conformances</span>
            <span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-slate-100 text-slate-600">
              {findings.length}
            </span>
          </h3>
          <p className="text-xs text-slate-500 mt-0.5">
            Rule engine & stateful machine evaluation mapped to RFC 7296, 8247, and 8221 standards.
          </p>
        </div>

        <div className="relative w-full sm:w-64">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            placeholder="Search rule, RFC, title..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all"
          />
        </div>
      </div>

      <div className="flex items-center gap-2 mt-4 overflow-x-auto pb-1 text-xs">
        <span className="text-slate-400 text-xs font-medium flex items-center gap-1 shrink-0">
          <Filter className="w-3.5 h-3.5" /> Filter:
        </span>
        {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
          <button
            key={sev}
            onClick={() => setFilterSeverity(sev)}
            className={`px-2.5 py-1 rounded-lg font-medium transition-all shrink-0 cursor-pointer ${
              filterSeverity === sev
                ? 'bg-indigo-600 text-white shadow-2xs'
                : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
            }`}
          >
            {sev}
          </button>
        ))}
      </div>

      <div className="mt-4 border border-slate-200/80 rounded-xl overflow-hidden">
        {filteredFindings.length === 0 ? (
          <div className="p-8 text-center text-slate-400 text-xs flex flex-col items-center justify-center">
            <CheckCircle2 className="w-8 h-8 text-emerald-500 mb-2" />
            <span className="font-medium text-slate-700">No findings match this filter.</span>
            <span className="mt-0.5">Either no vulnerabilities were detected or query does not match.</span>
          </div>
        ) : (
          <div className="divide-y divide-slate-100">
            {filteredFindings.map((f) => {
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
                <div key={f.id} className="transition-colors hover:bg-slate-50/70">
                  <div
                    onClick={() => toggleExpand(f.id)}
                    className="flex items-center justify-between p-4 cursor-pointer select-none"
                  >
                    <div className="flex items-center gap-3 min-w-0 pr-4">
                      <span className={`px-2 py-0.5 text-[10px] font-bold rounded-full border shrink-0 ${getSeverityBadge(f.severity)}`}>
                        {f.severity}
                      </span>
                      <span className="text-xs font-mono font-medium text-slate-500 shrink-0 hidden sm:inline">
                        {f.rule_id}
                      </span>
                      <span className="text-xs font-semibold text-slate-800 truncate">
                        {f.title}
                      </span>
                    </div>

                    <div className="flex items-center gap-3 shrink-0">
                      {f.rfc_reference && (
                        <span className="text-[11px] font-medium text-indigo-600 bg-indigo-50 px-2 py-0.5 rounded border border-indigo-100 hidden md:inline">
                          {f.rfc_reference}
                        </span>
                      )}
                      {isExpanded ? (
                        <ChevronUp className="w-4 h-4 text-slate-400" />
                      ) : (
                        <ChevronDown className="w-4 h-4 text-slate-400" />
                      )}
                    </div>
                  </div>

                  {isExpanded && (
                    <div className="px-5 pb-5 pt-1 bg-slate-50/50 border-t border-slate-100 text-xs space-y-3">
                      <div>
                        <span className="font-semibold text-slate-700">Description:</span>
                        <p className="mt-1 text-slate-600 leading-relaxed">{f.description}</p>
                      </div>

                      {f.remediation_hint && (
                        <div className="p-3 bg-emerald-50/70 border border-emerald-200/80 rounded-xl text-emerald-800">
                          <span className="font-bold flex items-center gap-1.5 text-emerald-900 mb-1">
                            <CheckCircle2 className="w-3.5 h-3.5" /> Actionable Remediation:
                          </span>
                          <span>{f.remediation_hint}</span>
                        </div>
                      )}

                      {evidenceObj && (
                        <div>
                          <span className="font-semibold text-slate-700">Offending Parameters / Evidence:</span>
                          <pre className="mt-1 p-2.5 bg-white border border-slate-200 rounded-lg text-[11px] font-mono text-slate-800 overflow-x-auto">
                            {JSON.stringify(evidenceObj, null, 2)}
                          </pre>
                        </div>
                      )}

                      <div className="flex items-center gap-3 text-[11px] text-slate-400 pt-1">
                        <span>Category: {f.category}</span>
                        <span>•</span>
                        <span>Standard: {f.rfc_reference || 'RFC 7296'}</span>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
