import React from 'react';
import { AlertTriangle, ShieldCheck, ShieldAlert, KeyRound, Lock, Hash, Shield, Cpu, ExternalLink } from 'lucide-react';

export default function ScoreGauge({ assessment, findings = [], sessions = [] }) {
  if (!assessment) return null;

  const score = Math.round(assessment.overall_score || 0);
  const riskLevel = (assessment.risk_level || 'SECURE').toUpperCase();

  const config = {
    CRITICAL: {
      strokeColor: '#E11D48',
      bgBadge: 'bg-rose-50 text-rose-800 border-rose-200',
      label: 'CRITICAL VULNERABILITY',
      summary: 'Session exposes cleartext credentials or deprecated ciphers susceptible to offline brute-force or collision attacks.',
    },
    HIGH: {
      strokeColor: '#EA580C',
      bgBadge: 'bg-orange-50 text-orange-800 border-orange-200',
      label: 'HIGH RISK EXPOSURE',
      summary: 'Handshake negotiates deprecated Diffie-Hellman or hashing algorithms prohibited by RFC 8247.',
    },
    MEDIUM: {
      strokeColor: '#D97706',
      bgBadge: 'bg-amber-50 text-amber-800 border-amber-200',
      label: 'MEDIUM RISK',
      summary: 'Sub-optimal cryptographic parameters or absent Perfect Forward Secrecy (PFS).',
    },
    LOW: {
      strokeColor: '#2563EB',
      bgBadge: 'bg-blue-50 text-blue-800 border-blue-200',
      label: 'LOW RISK',
      summary: 'Minor configuration warnings or non-critical RFC recommendations.',
    },
    SECURE: {
      strokeColor: '#059669',
      bgBadge: 'bg-emerald-50 text-emerald-800 border-emerald-200',
      label: 'RFC 8247 COMPLIANT',
      summary: 'Cryptographic proposal matches modern security profiles (AEAD AES-GCM-256, DH Group 14/19+, SHA-256).',
    },
  }[riskLevel] || {
    strokeColor: '#059669',
    bgBadge: 'bg-emerald-50 text-emerald-800 border-emerald-200',
    label: riskLevel,
    summary: 'Assessment completed.',
  };

  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const arcLength = circumference * 0.75;
  const strokeDashoffset = arcLength - (arcLength * Math.min(score, 100)) / 100;

  const counts = {
    CRITICAL: findings.filter((f) => f.severity === 'CRITICAL').length,
    HIGH: findings.filter((f) => f.severity === 'HIGH').length,
    MEDIUM: findings.filter((f) => f.severity === 'MEDIUM').length,
    LOW: findings.filter((f) => f.severity === 'LOW').length,
  };

  // Inspect cryptographic attributes from findings or default session
  const hasWeakDH = findings.some((f) => f.rule_id?.includes('DH') || f.title?.includes('Diffie-Hellman'));
  const hasLegacyCipher = findings.some((f) => f.rule_id?.includes('CIPHER') || f.title?.includes('3DES'));
  const hasWeakHash = findings.some((f) => f.rule_id?.includes('INTEG') || f.title?.includes('MD5'));
  const hasCleartextPsk = findings.some((f) => f.rule_id?.includes('AGGRESSIVE') || f.title?.includes('Aggressive'));

  return (
    <div className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
      
      {/* Card Header Bar */}
      <div className="px-5 py-3 border-b border-slate-200/80 bg-slate-50/50 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono font-bold uppercase tracking-wider text-slate-800">
            Cryptographic Posture & RFC Compliance
          </span>
          <span className="text-slate-300">•</span>
          <span className="text-[11px] font-mono text-slate-500">
            Assessment ID: {assessment.upload_id ? assessment.upload_id.slice(0, 12) : 'demo-run'}
          </span>
        </div>

        <div className="flex items-center gap-2">
          <span className={`px-2 py-0.5 text-[10px] font-mono font-bold uppercase tracking-wide rounded border ${config.bgBadge}`}>
            {config.label}
          </span>
        </div>
      </div>

      <div className="p-5 grid grid-cols-1 md:grid-cols-12 gap-6 items-center">
        
        {/* Col 1: Radial Gauge (3 cols) */}
        <div className="md:col-span-3 flex flex-col items-center justify-center border-b md:border-b-0 md:border-r border-slate-200/80 pb-5 md:pb-0 md:pr-4">
          <div className="relative w-36 h-36 flex items-center justify-center">
            <svg className="w-full h-full transform -rotate-135" viewBox="0 0 130 130">
              <circle
                cx="65"
                cy="65"
                r={radius}
                fill="none"
                stroke="#F1F5F9"
                strokeWidth="10"
                strokeDasharray={arcLength}
                strokeDashoffset="0"
                strokeLinecap="round"
              />
              <circle
                cx="65"
                cy="65"
                r={radius}
                fill="none"
                stroke={config.strokeColor}
                strokeWidth="10"
                strokeDasharray={arcLength}
                strokeDashoffset={strokeDashoffset}
                strokeLinecap="round"
                className="transition-all duration-700 ease-out"
              />
            </svg>

            <div className="absolute flex flex-col items-center justify-center select-none text-center">
              <span className="text-3xl font-extrabold text-slate-900 font-mono tracking-tight">
                {score}
              </span>
              <span className="text-[10px] font-mono font-semibold text-slate-400 uppercase">
                / 100 Risk
              </span>
            </div>
          </div>

          <div className="mt-2 text-center">
            <span className="text-[11px] font-mono text-slate-500">
              NetSentry Composite Index
            </span>
          </div>
        </div>

        {/* Col 2: Detected Cryptographic Suite Parameters (5 cols) */}
        <div className="md:col-span-5 space-y-2 border-b md:border-b-0 md:border-r border-slate-200/80 pb-5 md:pb-0 md:pr-4">
          <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-semibold block">
            Negotiated Cryptosuite Parameters
          </span>

          <div className="grid grid-cols-2 gap-2 text-xs">
            {/* Key Exchange */}
            <div className="p-2 rounded bg-slate-50 border border-slate-200/80">
              <div className="flex items-center gap-1.5 text-slate-500 text-[10px] font-mono">
                <KeyRound className="w-3 h-3 text-slate-400" /> Key Exchange (DH)
              </div>
              <div className="mt-1 font-mono font-semibold text-slate-800 truncate text-[11px]">
                {hasWeakDH ? 'Group 2 (1024-bit MODP)' : 'Group 19 (ECP-256)'}
              </div>
              <span className={`inline-block mt-0.5 text-[9px] font-mono font-bold px-1 rounded ${hasWeakDH ? 'bg-rose-100 text-rose-700' : 'bg-emerald-100 text-emerald-700'}`}>
                {hasWeakDH ? 'FAIL: RFC 8247 §2.4' : 'PASS: RFC 8247'}
              </span>
            </div>

            {/* Bulk Cipher */}
            <div className="p-2 rounded bg-slate-50 border border-slate-200/80">
              <div className="flex items-center gap-1.5 text-slate-500 text-[10px] font-mono">
                <Lock className="w-3 h-3 text-slate-400" /> Bulk Encryption
              </div>
              <div className="mt-1 font-mono font-semibold text-slate-800 truncate text-[11px]">
                {hasLegacyCipher ? '3DES-CBC (64-bit block)' : 'AES-GCM-256'}
              </div>
              <span className={`inline-block mt-0.5 text-[9px] font-mono font-bold px-1 rounded ${hasLegacyCipher ? 'bg-rose-100 text-rose-700' : 'bg-emerald-100 text-emerald-700'}`}>
                {hasLegacyCipher ? 'FAIL: RFC 8221 §5' : 'PASS: RFC 8221'}
              </span>
            </div>

            {/* Integrity / PRF */}
            <div className="p-2 rounded bg-slate-50 border border-slate-200/80">
              <div className="flex items-center gap-1.5 text-slate-500 text-[10px] font-mono">
                <Hash className="w-3 h-3 text-slate-400" /> Integrity / PRF
              </div>
              <div className="mt-1 font-mono font-semibold text-slate-800 truncate text-[11px]">
                {hasWeakHash ? 'HMAC-MD5 (128-bit)' : 'PRF-SHA256'}
              </div>
              <span className={`inline-block mt-0.5 text-[9px] font-mono font-bold px-1 rounded ${hasWeakHash ? 'bg-rose-100 text-rose-700' : 'bg-emerald-100 text-emerald-700'}`}>
                {hasWeakHash ? 'FAIL: RFC 8247 §2.2' : 'PASS: RFC 8247'}
              </span>
            </div>

            {/* Exchange Mode */}
            <div className="p-2 rounded bg-slate-50 border border-slate-200/80">
              <div className="flex items-center gap-1.5 text-slate-500 text-[10px] font-mono">
                <Shield className="w-3 h-3 text-slate-400" /> Exchange Mode
              </div>
              <div className="mt-1 font-mono font-semibold text-slate-800 truncate text-[11px]">
                {hasCleartextPsk ? 'IKEv1 Aggressive (PSK)' : 'IKEv2 Main (Cert)'}
              </div>
              <span className={`inline-block mt-0.5 text-[9px] font-mono font-bold px-1 rounded ${hasCleartextPsk ? 'bg-rose-100 text-rose-700' : 'bg-emerald-100 text-emerald-700'}`}>
                {hasCleartextPsk ? 'FAIL: RFC 2409 §5.4' : 'PASS: RFC 7296'}
              </span>
            </div>
          </div>
        </div>

        {/* Col 3: Findings Breakdown & Summary (4 cols) */}
        <div className="md:col-span-4 flex flex-col justify-between h-full space-y-3">
          <div>
            <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-semibold block mb-1.5">
              Severity Distribution
            </span>
            <div className="grid grid-cols-4 gap-1.5 text-center">
              <div className="p-1.5 rounded bg-rose-50 border border-rose-200/80">
                <div className="text-[10px] font-mono uppercase text-rose-700 font-semibold">Crit</div>
                <div className="text-base font-bold text-rose-800 font-mono">{counts.CRITICAL}</div>
              </div>
              <div className="p-1.5 rounded bg-orange-50 border border-orange-200/80">
                <div className="text-[10px] font-mono uppercase text-orange-700 font-semibold">High</div>
                <div className="text-base font-bold text-orange-800 font-mono">{counts.HIGH}</div>
              </div>
              <div className="p-1.5 rounded bg-amber-50 border border-amber-200/80">
                <div className="text-[10px] font-mono uppercase text-amber-700 font-semibold">Med</div>
                <div className="text-base font-bold text-amber-800 font-mono">{counts.MEDIUM}</div>
              </div>
              <div className="p-1.5 rounded bg-slate-50 border border-slate-200/80">
                <div className="text-[10px] font-mono uppercase text-slate-600 font-semibold">ML Anom</div>
                <div className="text-base font-bold text-slate-800 font-mono">
                  {assessment.ml_anomaly_score ? assessment.ml_anomaly_score.toFixed(2) : '0.00'}
                </div>
              </div>
            </div>
          </div>

          <div className="p-2.5 rounded bg-slate-50 border border-slate-200/80 text-[11px] text-slate-600 leading-relaxed">
            {assessment.executive_summary || config.summary}
          </div>
        </div>

      </div>
    </div>
  );
}

