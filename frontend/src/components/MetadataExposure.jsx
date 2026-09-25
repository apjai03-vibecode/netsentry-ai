import React from 'react';
import { 
  Eye, 
  ShieldAlert, 
  ShieldCheck, 
  Lock, 
  Unlock, 
  Globe, 
  Share2, 
  AlertTriangle,
  Info
} from 'lucide-react';

export default function MetadataExposure({ metadataExposureData }) {
  const exposure = metadataExposureData || {
    exposure_level: 'MEDIUM',
    exposure_score: 45.0,
    observable_elements: [
      {
        category: 'Network Endpoints',
        element: 'Public IP Pair (192.168.1.100 <-> 198.51.100.1)',
        impact: 'Exposes communicating gateway entities and geographical routing paths to eavesdroppers.'
      },
      {
        category: 'Signaling Ports',
        element: 'UDP 500 / UDP 4500 (NAT-Traversal Active)',
        impact: 'Identifies presence of IPsec daemon and address-translating intermediate firewall.'
      },
      {
        category: 'Security Parameter Indexes',
        element: 'Initiator SPI (11223344...) / ESP SPI (3a4b5c6d)',
        impact: 'Allows passive correlation of multiple sessions to the same user or security association over time.'
      },
      {
        category: 'Traffic Flow Dynamics',
        element: 'Flow Volume & Sizing Profile (ESP payload lengths)',
        impact: 'Packet sizes and inter-arrival timing expose behavioral application signatures.'
      }
    ],
    confidential_elements: [
      {
        category: 'Application Payload Data',
        protection: 'Encrypted inside ESP payloads (AES-GCM-256 / AES-CBC-256)'
      },
      {
        category: 'Internal Subnets & Private IPs',
        protection: 'Encapsulated within outer IPsec tunnel headers (Tunnel Mode)'
      },
      {
        category: 'User Authentication Credentials',
        protection: 'Protected by Diffie-Hellman Shared Secret (Encrypted IKE_AUTH)'
      }
    ],
    inference_analysis: [
      'Observer identifies continuous site-to-site communication between 192.168.1.100 and 198.51.100.1.',
      'Client resides behind a NAT firewall or cellular carrier-grade NAT (CGNAT).',
      'Traffic timing and packet length distributions expose behavioral application patterns (e.g., interactive Web vs. VoIP).'
    ],
    mitigation_recommendations: [
      'Deploy IPsec Traffic Flow Confidentiality (TFC) padding per RFC 4303 to conceal true packet lengths.',
      'Maintain strict IKEv2-only policies with ephemeral Diffie-Hellman re-keying to prevent session correlation.'
    ]
  };

  const getScoreColor = (score) => {
    if (score >= 65) return 'text-red-600 dark:text-red-400 border-red-500';
    if (score >= 40) return 'text-amber-600 dark:text-amber-400 border-amber-500';
    return 'text-emerald-600 dark:text-emerald-400 border-emerald-500';
  };

  return (
    <div className="bg-white dark:bg-[#111827] rounded-[10px] border border-[#E2E8F0] dark:border-slate-800 shadow-2xs overflow-hidden">
      {/* Header */}
      <div className="p-5 border-b border-[#E2E8F0] dark:border-slate-800">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20">
                METADATA EXPOSURE & SIDE-CHANNELS
              </span>
              <span className="text-xs text-[#64748B] dark:text-slate-400 font-mono">
                Passive Wire Traffic Analysis Assessment
              </span>
            </div>
            <h2 className="text-lg font-bold text-[#0F172A] dark:text-[#F8FAFC]">
              Cleartext Wire Leakage & Privacy Boundary
            </h2>
          </div>

          {/* Exposure Score Badge */}
          <div className="flex items-center gap-3">
            <div className={`px-4 py-2 rounded-lg border bg-slate-50 dark:bg-slate-900 flex items-center gap-3 ${getScoreColor(exposure.exposure_score || 45)}`}>
              <div>
                <span className="text-[10px] uppercase font-mono block text-slate-500">Leakage Index</span>
                <span className="text-xl font-bold font-mono">
                  {exposure.exposure_score?.toFixed(1) || '45.0'}<span className="text-xs text-slate-400">/100</span>
                </span>
              </div>
              <span className="text-xs font-mono font-bold uppercase">
                {exposure.exposure_level || 'MEDIUM'} EXPOSURE
              </span>
            </div>
          </div>
        </div>
      </div>

      <div className="p-5 space-y-6">
        {/* Observable Elements (What Leaks) */}
        <div>
          <div className="flex items-center gap-2 mb-3">
            <Unlock className="w-4 h-4 text-amber-500" />
            <h3 className="text-xs font-mono uppercase font-bold text-[#0F172A] dark:text-slate-200">
              Observable Wire Elements (Visible to Passive Eavesdroppers)
            </h3>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
            {exposure.observable_elements?.map((elem, idx) => (
              <div key={idx} className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-900/40">
                <span className="text-[10px] font-bold text-amber-600 dark:text-amber-400 block mb-1">
                  {elem.category}
                </span>
                <span className="font-semibold text-slate-800 dark:text-slate-200 block mb-1">
                  {elem.element}
                </span>
                <p className="text-slate-600 dark:text-slate-400 text-[11px] leading-relaxed">
                  {elem.impact}
                </p>
              </div>
            ))}
          </div>
        </div>

        {/* Confidential Elements (Guaranteed by Encapsulation) */}
        <div>
          <div className="flex items-center gap-2 mb-3">
            <Lock className="w-4 h-4 text-emerald-500" />
            <h3 className="text-xs font-mono uppercase font-bold text-[#0F172A] dark:text-slate-200">
              Confidential Elements (Protected by IPsec Cryptographic Boundary)
            </h3>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono">
            {exposure.confidential_elements?.map((elem, idx) => (
              <div key={idx} className="p-3 rounded-lg border border-emerald-200 dark:border-emerald-950 bg-emerald-50/40 dark:bg-emerald-950/20">
                <span className="text-[10px] font-bold text-emerald-600 dark:text-emerald-400 block mb-1">
                  {elem.category}
                </span>
                <p className="text-slate-700 dark:text-slate-300 text-[11px] leading-relaxed">
                  {elem.protection}
                </p>
              </div>
            ))}
          </div>
        </div>

        {/* Inferences & Mitigations */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
          {/* Eavesdropper Inferences */}
          <div className="p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950">
            <span className="font-bold text-slate-700 dark:text-slate-300 block mb-2">
              Inferences Possible via Passive Telemetry:
            </span>
            <ul className="space-y-2 text-slate-600 dark:text-slate-400">
              {exposure.inference_analysis?.map((inf, idx) => (
                <li key={idx} className="flex items-start gap-2">
                  <span className="text-amber-500 font-bold">•</span>
                  <span>{inf}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Mitigation Recommendations */}
          <div className="p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950">
            <span className="font-bold text-slate-700 dark:text-slate-300 block mb-2">
              Privacy Hardening Recommendations:
            </span>
            <ul className="space-y-2 text-slate-600 dark:text-slate-400">
              {exposure.mitigation_recommendations?.map((mit, idx) => (
                <li key={idx} className="flex items-start gap-2">
                  <span className="text-indigo-500 font-bold">•</span>
                  <span>{mit}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}
