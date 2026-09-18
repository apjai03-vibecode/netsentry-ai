import React from 'react';
import { AlertTriangle, ShieldCheck, ShieldAlert, Zap, HelpCircle } from 'lucide-react';

export default function ScoreGauge({ assessment, findings = [] }) {
  if (!assessment) return null;

  const score = Math.round(assessment.overall_score || 0);
  const riskLevel = (assessment.risk_level || 'SECURE').toUpperCase();

  const config = {
    CRITICAL: {
      color: '#EF4444',
      bgPill: 'bg-rose-50 text-rose-700 border-rose-200',
      label: 'Critical Risk',
      desc: 'Severe cryptographic vulnerabilities detected. Immediate remediation required.',
    },
    HIGH: {
      color: '#F97316',
      bgPill: 'bg-orange-50 text-orange-700 border-orange-200',
      label: 'High Risk',
      desc: 'Deprecated cipher suites or handshake sequencing flaws present.',
    },
    MEDIUM: {
      color: '#F59E0B',
      bgPill: 'bg-amber-50 text-amber-700 border-amber-200',
      label: 'Medium Risk',
      desc: 'Sub-optimal parameters or absent forward secrecy options.',
    },
    LOW: {
      color: '#3B82F6',
      bgPill: 'bg-blue-50 text-blue-700 border-blue-200',
      label: 'Low Risk',
      desc: 'Minor warnings or non-critical configuration deviations.',
    },
    SECURE: {
      color: '#10B981',
      bgPill: 'bg-emerald-50 text-emerald-700 border-emerald-200',
      label: 'Healthy & Secure',
      desc: 'Compliant with RFC 8247 & RFC 8221 standards. Cryptography is robust.',
    },
  }[riskLevel] || {
    color: '#10B981',
    bgPill: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    label: riskLevel,
    desc: 'Session evaluated.',
  };

  const radius = 58;
  const circumference = 2 * Math.PI * radius;
  const arcLength = circumference * 0.75;
  const strokeDashoffset = arcLength - (arcLength * Math.min(score, 100)) / 100;

  const counts = {
    CRITICAL: findings.filter((f) => f.severity === 'CRITICAL').length,
    HIGH: findings.filter((f) => f.severity === 'HIGH').length,
    MEDIUM: findings.filter((f) => f.severity === 'MEDIUM').length,
    LOW: findings.filter((f) => f.severity === 'LOW').length,
  };

  return (
    <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs">
      <div className="flex flex-col lg:flex-row items-center justify-between gap-8">
        
        {/* Radial SVG Gauge */}
        <div className="flex flex-col items-center justify-center shrink-0">
          <div className="relative w-44 h-44 flex items-center justify-center">
            <svg className="w-full h-full transform -rotate-135" viewBox="0 0 140 140">
              <circle
                cx="70"
                cy="70"
                r={radius}
                fill="none"
                stroke="#F1F5F9"
                strokeWidth="12"
                strokeDasharray={arcLength}
                strokeDashoffset="0"
                strokeLinecap="round"
              />
              <circle
                cx="70"
                cy="70"
                r={radius}
                fill="none"
                stroke={config.color}
                strokeWidth="12"
                strokeDasharray={arcLength}
                strokeDashoffset={strokeDashoffset}
                strokeLinecap="round"
                className="transition-all duration-1000 ease-out"
              />
            </svg>

            <div className="absolute flex flex-col items-center justify-center text-center select-none">
              <span className="text-4xl font-extrabold tracking-tight text-slate-900">
                {score}
              </span>
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                / 100 Risk
              </span>
              <span className={`mt-1 text-[11px] px-2 py-0.5 rounded-full font-bold border ${config.bgPill}`}>
                {config.label}
              </span>
            </div>
          </div>
          <span className="text-xs text-slate-400 mt-1">Calculated by NetSentry RiskScorer</span>
        </div>

        {/* Executive Summary & Severity Breakdown */}
        <div className="flex-1 flex flex-col justify-between w-full">
          <div>
            <div className="flex items-center justify-between">
              <h3 className="text-base font-semibold text-slate-900 flex items-center gap-2">
                <span>Executive Security Assessment</span>
                {score >= 50 ? (
                  <AlertTriangle className="w-4 h-4 text-orange-500" />
                ) : (
                  <ShieldCheck className="w-4 h-4 text-emerald-500" />
                )}
              </h3>
              <span className="text-xs text-slate-500 font-mono">Job ID: {assessment.upload_id?.slice(0, 8)}...</span>
            </div>

            <p className="mt-2 text-sm text-slate-600 leading-relaxed bg-slate-50 p-3.5 rounded-xl border border-slate-200/80">
              {assessment.executive_summary || config.desc}
            </p>
          </div>

          {/* Quick Metrics Bar */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-4">
            <div className="p-2.5 rounded-xl bg-rose-50/70 border border-rose-100 flex flex-col">
              <span className="text-[11px] font-semibold text-rose-600 uppercase">Critical</span>
              <span className="text-xl font-bold text-rose-700">{counts.CRITICAL}</span>
            </div>
            <div className="p-2.5 rounded-xl bg-orange-50/70 border border-orange-100 flex flex-col">
              <span className="text-[11px] font-semibold text-orange-600 uppercase">High</span>
              <span className="text-xl font-bold text-orange-700">{counts.HIGH}</span>
            </div>
            <div className="p-2.5 rounded-xl bg-amber-50/70 border border-amber-100 flex flex-col">
              <span className="text-[11px] font-semibold text-amber-600 uppercase">Medium</span>
              <span className="text-xl font-bold text-amber-700">{counts.MEDIUM}</span>
            </div>
            <div className="p-2.5 rounded-xl bg-slate-100 border border-slate-200 flex flex-col">
              <span className="text-[11px] font-semibold text-slate-600 uppercase">ML Anomaly</span>
              <span className="text-xl font-bold text-slate-800">
                {assessment.ml_anomaly_score ? assessment.ml_anomaly_score.toFixed(2) : '0.00'}
              </span>
            </div>
          </div>

        </div>

      </div>
    </div>
  );
}
