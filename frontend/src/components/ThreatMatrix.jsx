import React, { useState } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Info, 
  Search, 
  ChevronDown, 
  ChevronUp, 
  ExternalLink,
  Filter,
  Eye,
  Activity,
  Lock
} from 'lucide-react';

export default function ThreatMatrix({ threatMatrixData, onSelectFinding }) {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState('ALL');
  const [selectedObs, setSelectedObs] = useState('ALL');
  const [expandedRow, setExpandedRow] = useState(null);

  const entries = threatMatrixData?.entries || [];
  const summary = threatMatrixData?.summary || {
    total_findings: entries.length,
    critical_count: entries.filter(e => e.severity === 'CRITICAL').length,
    high_count: entries.filter(e => e.severity === 'HIGH').length,
    medium_count: entries.filter(e => e.severity === 'MEDIUM').length,
    low_count: entries.filter(e => e.severity === 'LOW').length,
    observed_count: entries.filter(e => e.observability === 'OBSERVED').length,
    inferred_count: entries.filter(e => e.observability === 'INFERRED').length,
    not_observable_count: entries.filter(e => e.observability === 'NOT_OBSERVABLE').length,
  };

  const filteredEntries = entries.filter((entry) => {
    const matchesSearch = 
      entry.finding?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      entry.evidence?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      entry.reference?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      entry.recommendation?.toLowerCase().includes(searchQuery.toLowerCase());
    
    const matchesSeverity = selectedSeverity === 'ALL' || entry.severity === selectedSeverity;
    const matchesObs = selectedObs === 'ALL' || entry.observability === selectedObs;
    return matchesSearch && matchesSeverity && matchesObs;
  });

  const getSeverityBadge = (severity) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/30';
      case 'HIGH':
        return 'bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-500/30';
      case 'MEDIUM':
        return 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/30';
      case 'LOW':
        return 'bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/30';
      default:
        return 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30';
    }
  };

  const getObservabilityBadge = (obs) => {
    switch (obs) {
      case 'OBSERVED':
        return 'bg-teal-500/10 text-teal-700 dark:text-teal-300 border-teal-500/30';
      case 'INFERRED':
        return 'bg-purple-500/10 text-purple-700 dark:text-purple-300 border-purple-500/30';
      default:
        return 'bg-slate-500/10 text-slate-700 dark:text-slate-400 border-slate-500/30';
    }
  };

  return (
    <div className="bg-white dark:bg-[#111827] rounded-[10px] border border-[#E2E8F0] dark:border-slate-800 shadow-2xs overflow-hidden">
      {/* Header & Stats Banner */}
      <div className="p-5 border-b border-[#E2E8F0] dark:border-slate-800">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 mb-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 border border-indigo-500/20">
                7-COLUMN THREAT MATRIX
              </span>
              <span className="text-xs text-[#64748B] dark:text-slate-400 font-mono">
                SIH26160 Unified Cryptographic Audit
              </span>
            </div>
            <h2 className="text-lg font-bold text-[#0F172A] dark:text-[#F8FAFC]">
              Unified Protocol Vulnerability & Threat Matrix
            </h2>
          </div>

          {/* Quick Metrics */}
          <div className="flex items-center gap-2 flex-wrap text-xs font-mono">
            <div className="px-3 py-1.5 rounded-md bg-red-500/10 border border-red-500/20 text-red-600 dark:text-red-400 font-semibold">
              {summary.critical_count} Critical
            </div>
            <div className="px-3 py-1.5 rounded-md bg-orange-500/10 border border-orange-500/20 text-orange-600 dark:text-orange-400 font-semibold">
              {summary.high_count} High
            </div>
            <div className="px-3 py-1.5 rounded-md bg-teal-500/10 border border-teal-500/20 text-teal-700 dark:text-teal-300 font-semibold">
              {summary.observed_count} [Observed]
            </div>
            <div className="px-3 py-1.5 rounded-md bg-purple-500/10 border border-purple-500/20 text-purple-700 dark:text-purple-300 font-semibold">
              {summary.inferred_count} [Inferred]
            </div>
            <div className="px-3 py-1.5 rounded-md bg-slate-500/10 border border-slate-500/20 text-slate-700 dark:text-slate-400 font-semibold">
              {summary.not_observable_count} [Not Observable]
            </div>
          </div>
        </div>

        {/* Filter and Search Controls */}
        <div className="flex flex-col sm:flex-row gap-3 items-center justify-between pt-2">
          {/* Search bar */}
          <div className="relative w-full sm:w-80">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search findings, RFCs, evidence..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 text-xs font-mono rounded-md border border-[#E2E8F0] dark:border-slate-700 bg-slate-50 dark:bg-slate-900 text-[#0F172A] dark:text-slate-200 placeholder-slate-400 focus:outline-none focus:ring-1 focus:ring-indigo-500"
            />
          </div>

          {/* Filter Dropdowns */}
          <div className="flex items-center gap-2 w-full sm:w-auto">
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="px-2.5 py-1.5 text-xs font-mono rounded-md border border-[#E2E8F0] dark:border-slate-700 bg-slate-50 dark:bg-slate-900 text-[#0F172A] dark:text-slate-200 focus:outline-none focus:ring-1 focus:ring-indigo-500"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
              <option value="INFORMATIONAL">Informational</option>
            </select>

            <select
              value={selectedObs}
              onChange={(e) => setSelectedObs(e.target.value)}
              className="px-2.5 py-1.5 text-xs font-mono rounded-md border border-[#E2E8F0] dark:border-slate-700 bg-slate-50 dark:bg-slate-900 text-[#0F172A] dark:text-slate-200 focus:outline-none focus:ring-1 focus:ring-indigo-500"
            >
              <option value="ALL">All Taxonomy</option>
              <option value="OBSERVED">[OBSERVED]</option>
              <option value="INFERRED">[INFERRED]</option>
              <option value="NOT_OBSERVABLE">[NOT OBSERVABLE]</option>
            </select>
          </div>
        </div>
      </div>

      {/* 7-Column Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs font-mono border-collapse">
          <thead>
            <tr className="bg-slate-50 dark:bg-slate-900/60 border-b border-[#E2E8F0] dark:border-slate-800 text-[#64748B] dark:text-slate-400 uppercase text-[10px] tracking-wider">
              <th className="py-3 px-4 font-semibold w-1/4">1. Finding & Taxonomy</th>
              <th className="py-3 px-3 font-semibold text-center w-24">2. Severity</th>
              <th className="py-3 px-4 font-semibold w-1/5">3. Technical Evidence</th>
              <th className="py-3 px-4 font-semibold w-1/5">4. Security Impact</th>
              <th className="py-3 px-3 font-semibold text-center w-20">5. Conf</th>
              <th className="py-3 px-3 font-semibold w-28">6. RFC Citation</th>
              <th className="py-3 px-4 font-semibold w-1/4">7. Safe Recommendation</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#E2E8F0] dark:divide-slate-800">
            {filteredEntries.length === 0 ? (
              <tr>
                <td colSpan={7} className="py-8 text-center text-slate-400 dark:text-slate-500">
                  No threat matrix findings matched the specified filter criteria.
                </td>
              </tr>
            ) : (
              filteredEntries.map((entry, idx) => {
                const isExpanded = expandedRow === idx;
                return (
                  <React.Fragment key={entry.finding_id || idx}>
                    <tr 
                      onClick={() => setExpandedRow(isExpanded ? null : idx)}
                      className={`hover:bg-slate-50/80 dark:hover:bg-slate-800/40 cursor-pointer transition-colors ${
                        isExpanded ? 'bg-indigo-50/30 dark:bg-indigo-950/20' : ''
                      }`}
                    >
                      {/* 1. Finding & Taxonomy */}
                      <td className="py-3 px-4">
                        <div className="flex items-start gap-2">
                          <button className="mt-0.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200">
                            {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                          </button>
                          <div>
                            <div className="font-semibold text-[#0F172A] dark:text-slate-200 leading-tight">
                              {entry.finding}
                            </div>
                            <div className="flex items-center gap-1.5 mt-1">
                              <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold border ${getObservabilityBadge(entry.observability)}`}>
                                [{entry.observability || 'OBSERVED'}]
                              </span>
                              <span className="text-[10px] text-slate-400 font-mono">
                                {entry.category || 'CRYPTOGRAPHIC'}
                              </span>
                            </div>
                          </div>
                        </div>
                      </td>

                      {/* 2. Severity */}
                      <td className="py-3 px-3 text-center">
                        <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadge(entry.severity)}`}>
                          {entry.severity}
                        </span>
                      </td>

                      {/* 3. Evidence */}
                      <td className="py-3 px-4 text-slate-600 dark:text-slate-300 truncate max-w-xs" title={entry.evidence}>
                        {entry.evidence}
                      </td>

                      {/* 4. Impact */}
                      <td className="py-3 px-4 text-slate-600 dark:text-slate-300 truncate max-w-xs" title={entry.impact}>
                        {entry.impact}
                      </td>

                      {/* 5. Confidence */}
                      <td className="py-3 px-3 text-center font-bold text-slate-700 dark:text-slate-300">
                        {entry.confidence || 'HIGH'}
                      </td>

                      {/* 6. RFC Citation */}
                      <td className="py-3 px-3 text-indigo-600 dark:text-indigo-400 font-semibold truncate max-w-28" title={entry.reference}>
                        {entry.reference}
                      </td>

                      {/* 7. Recommendation */}
                      <td className="py-3 px-4 text-slate-700 dark:text-slate-300 truncate max-w-xs" title={entry.recommendation}>
                        {entry.recommendation}
                      </td>
                    </tr>

                    {/* Expandable Technical Deep-Dive Row */}
                    {isExpanded && (
                      <tr className="bg-slate-50/70 dark:bg-slate-900/40">
                        <td colSpan={7} className="px-6 py-4">
                          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
                            <div className="p-3 bg-white dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-800">
                              <span className="font-bold text-slate-700 dark:text-slate-300 block mb-1">
                                Complete Evidence & Context:
                              </span>
                              <p className="text-slate-600 dark:text-slate-400 break-words leading-relaxed">
                                {entry.evidence}
                              </p>
                            </div>

                            <div className="p-3 bg-white dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-800">
                              <span className="font-bold text-slate-700 dark:text-slate-300 block mb-1">
                                Exploitation & Threat Impact:
                              </span>
                              <p className="text-slate-600 dark:text-slate-400 break-words leading-relaxed">
                                {entry.impact}
                              </p>
                            </div>

                            <div className="p-3 bg-white dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-800">
                              <span className="font-bold text-slate-700 dark:text-slate-300 block mb-1">
                                Safe Remediation Guidance:
                              </span>
                              <p className="text-slate-600 dark:text-slate-400 break-words leading-relaxed mb-2">
                                {entry.recommendation}
                              </p>
                              <div className="text-[10px] text-indigo-600 dark:text-indigo-400 font-semibold">
                                Standard: {entry.reference}
                              </div>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Footer Note */}
      <div className="p-3 bg-slate-50 dark:bg-slate-900/60 border-t border-[#E2E8F0] dark:border-slate-800 text-[11px] font-mono text-[#64748B] dark:text-slate-400 flex items-center justify-between">
        <span>Showing {filteredEntries.length} of {entries.length} Threat Matrix items</span>
        <span className="text-[10px]">NetSentry Deterministic RFC + FSM + ML Classifier Pipeline</span>
      </div>
    </div>
  );
}
