import React, { useState } from 'react';
import { Cpu, HelpCircle, ArrowRight, ShieldCheck, AlertTriangle, Layers, Info } from 'lucide-react';

export default function ModelExplanation({ assessment }) {
  const [showFormula, setShowFormula] = useState(false);

  const shapFeatures = [
    {
      feature: 'Weak DH Group (Group 1 / 2 / 5)',
      impact: 0.92,
      type: 'positive',
      category: 'Key Exchange',
      explanation: 'Uses sub-2048-bit prime modulus vulnerable to discrete logarithm precomputation (Logjam attack).',
    },
    {
      feature: 'Deprecated 3DES / DES Cipher',
      impact: 0.88,
      type: 'positive',
      category: 'Encryption',
      explanation: '64-bit block size vulnerable to Sweet32 birthday collision attacks in high-throughput tunnels.',
    },
    {
      feature: 'IKEv1 Protocol Legacy Mode',
      impact: 0.65,
      type: 'positive',
      category: 'Protocol Architecture',
      explanation: 'Transmits initiator ID and pre-shared key hash before encryption in Aggressive Mode.',
    },
    {
      feature: 'Broken Hash (MD5 / SHA-1)',
      impact: 0.55,
      type: 'positive',
      category: 'Integrity / PRF',
      explanation: 'Cryptographic collision attacks compromise integrity validation and digital signatures.',
    },
    {
      feature: 'RFC 8247 DH Group 14 / 19 (MODP-2048 / ECP-256)',
      impact: -0.85,
      type: 'negative',
      category: 'Protective Baseline',
      explanation: 'Provides minimum 112-bit to 128-bit classical security resistance recommended by IETF.',
    },
    {
      feature: 'Perfect Forward Secrecy (PFS Enabled)',
      impact: -0.45,
      type: 'negative',
      category: 'Protective Baseline',
      explanation: 'Generates independent ephemeral keys for Phase 2, preventing retrospective decryption if private key leaks.',
    },
  ];

  const maxAbsImpact = 1.0;

  return (
    <section className="bg-white rounded-[10px] border border-[#E2E8F0] shadow-2xs overflow-hidden">
      
      {/* Header Bar */}
      <div className="px-5 py-4 border-b border-[#E2E8F0] bg-[#F6F8FB]/80 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Cpu className="w-4 h-4 text-[#4F46E5]" />
            <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-[#0F172A]">
              Model Explanation
            </h2>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-indigo-50 text-[#4F46E5] border border-indigo-200 font-bold">
              Tree SHAP Attribution
            </span>
          </div>
          <p className="text-[11px] text-[#64748B] font-mono">
            Tree SHAP feature attribution explaining model decisions and cryptographic risk drivers
          </p>
        </div>

        {/* Legend */}
        <div className="flex items-center gap-4 text-xs font-mono">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-[3px] bg-[#DC2626]" />
            <span className="text-[#0F172A] font-semibold text-[11px]">Positive (Increases Risk)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-[3px] bg-[#059669]" />
            <span className="text-[#0F172A] font-semibold text-[11px]">Negative (Protective Factor)</span>
          </div>
        </div>
      </div>

      <div className="p-5 space-y-5">
        
        {/* Attribution Bars */}
        <div className="space-y-3.5">
          {shapFeatures.map((item, idx) => {
            const isPos = item.type === 'positive';
            const widthPct = Math.round((Math.abs(item.impact) / maxAbsImpact) * 100);

            return (
              <div
                key={idx}
                className="p-3 rounded-[8px] bg-[#F6F8FB] border border-[#E2E8F0] space-y-1.5 transition-colors hover:border-slate-300"
              >
                {/* Title & Badge */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 text-xs font-mono">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-[#0F172A]">
                      {item.feature}
                    </span>
                    <span className="text-[10px] text-slate-400 font-normal">
                      • {item.category}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <span
                      className={`text-xs font-bold font-mono px-2 py-0.5 rounded-[4px] ${
                        isPos
                          ? 'bg-rose-50 text-[#DC2626] border border-rose-200'
                          : 'bg-emerald-50 text-[#059669] border border-emerald-200'
                      }`}
                    >
                      {isPos ? `+${item.impact.toFixed(2)}` : item.impact.toFixed(2)} SHAP
                    </span>
                    <span className="text-[10px] text-[#64748B] font-medium hidden sm:inline">
                      {isPos ? 'Vulnerability Driver' : 'Protective Factor'}
                    </span>
                  </div>
                </div>

                {/* Relative Bar */}
                <div className="w-full bg-slate-200/80 rounded-full h-2 overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all duration-500 ${
                      isPos ? 'bg-[#DC2626]' : 'bg-[#059669]'
                    }`}
                    style={{ width: `${widthPct}%` }}
                  />
                </div>

                {/* Explanation text */}
                <p className="text-[11px] text-[#64748B] font-sans leading-tight">
                  {item.explanation}
                </p>
              </div>
            );
          })}
        </div>

        {/* Technical Explainer Footer */}
        <div className="p-3.5 rounded-[8px] bg-white border border-[#E2E8F0] text-xs font-mono space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-bold uppercase tracking-wider text-[#0F172A] flex items-center gap-1.5">
              <Info className="w-3.5 h-3.5 text-[#4F46E5]" />
              <span>How Tree SHAP Explains NetSentry Decisions</span>
            </span>
            <button
              onClick={() => setShowFormula(!showFormula)}
              className="text-[11px] text-[#4F46E5] hover:underline cursor-pointer"
            >
              {showFormula ? 'Hide Formulation' : 'View Mathematical Formulation'}
            </button>
          </div>

          <p className="text-[11px] text-[#64748B] font-sans leading-relaxed">
            Tree SHAP computes exact Shapley values in polynomial time <span className="font-mono">O(TLD²)</span> by evaluating feature contributions across all split trees. Rather than treating XGBoost as an uninterpretable black box, each detected parameter receives an additive credit score that reconstructs the final log-odds vulnerability classification.
          </p>

          {showFormula && (
            <div className="p-3 bg-[#0F172A] text-slate-100 rounded-[6px] text-[11px] font-mono overflow-x-auto border border-slate-800 space-y-1">
              <div className="text-indigo-400 font-bold">SHAP Value Additive Formula:</div>
              <div>f(x) = E[f(x)] + Σ φ_i(x)</div>
              <div className="text-slate-400 text-[10px] pt-1">
                Where <span className="text-slate-200">f(x)</span> is the session risk output, <span className="text-slate-200">E[f(x)] = 0.50</span> is the base rate, and <span className="text-slate-200">φ_i</span> represents the Shapley contribution of feature <span className="text-slate-200">i</span>.
              </div>
            </div>
          )}
        </div>

      </div>

    </section>
  );
}
