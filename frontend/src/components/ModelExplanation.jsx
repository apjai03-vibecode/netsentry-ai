import React, { useState } from 'react';
import { Cpu, Info } from 'lucide-react';

export default function ModelExplanation({ assessment }) {
  const [showFormula, setShowFormula] = useState(false);

  const shapFeatures = [
    {
      feature: 'Weak DH Group 1/2/5',
      impact: 0.92,
      type: 'positive',
      category: 'Key Exchange',
      explanation: 'Uses sub-2048-bit prime modulus vulnerable to discrete logarithm precomputation (Logjam attack).',
    },
    {
      feature: 'Deprecated 3DES / DES',
      impact: 0.88,
      type: 'positive',
      category: 'Bulk Cipher',
      explanation: '64-bit block size vulnerable to Sweet32 birthday collision attacks in high-throughput tunnels.',
    },
    {
      feature: 'IKEv1 Protocol Legacy Flag',
      impact: 0.65,
      type: 'positive',
      category: 'Protocol Architecture',
      explanation: 'Transmits initiator ID and pre-shared key hash before encryption in Aggressive Mode.',
    },
    {
      feature: 'RFC 8247 DH Group 14/19',
      impact: -0.85,
      type: 'negative',
      category: 'Protective Baseline',
      explanation: 'Provides minimum 112-bit to 128-bit classical security resistance recommended by IETF.',
    },
    {
      feature: 'Perfect Forward Secrecy Enabled',
      impact: -0.45,
      type: 'negative',
      category: 'Protective Baseline',
      explanation: 'Generates independent ephemeral keys for Phase 2, preventing retrospective decryption if private key leaks.',
    },
  ];

  const maxAbsImpact = 1.0;

  return (
    <section className="bg-white dark:bg-[#111827] rounded-[10px] border border-[#E2E8F0] dark:border-slate-800 shadow-2xs overflow-hidden transition-colors">
      
      {/* Header Bar */}
      <div className="px-5 py-4 border-b border-[#E2E8F0] dark:border-slate-800 bg-[#F6F8FB]/80 dark:bg-[#0F172A]/70 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Cpu className="w-4 h-4 text-[#4F46E5] dark:text-indigo-400" />
            <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-[#0F172A] dark:text-[#F8FAFC]">
              Model Explanation
            </h2>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-indigo-50 dark:bg-indigo-950/40 text-[#4F46E5] dark:text-indigo-400 border border-indigo-200 dark:border-indigo-900/50 font-bold">
              Tree SHAP Feature Attribution
            </span>
          </div>
          <p className="text-[11px] text-[#64748B] dark:text-slate-400 font-mono">
            Tree SHAP feature attribution explaining model decisions.
          </p>
        </div>

        {/* Legend */}
        <div className="flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-4 text-xs font-mono">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-[3px] bg-[#DC2626]" />
            <span className="text-[#0F172A] dark:text-slate-300 font-semibold text-[11px]">Positive contribution → increases vulnerability</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-[3px] bg-[#059669]" />
            <span className="text-[#0F172A] dark:text-slate-300 font-semibold text-[11px]">Negative contribution → protective factor</span>
          </div>
        </div>
      </div>

      <div className="p-5 space-y-5">
        
        {/* Horizontal Contribution Bars in Descending Importance */}
        <div className="space-y-3">
          {shapFeatures.map((item, idx) => {
            const isPos = item.type === 'positive';
            const widthPct = Math.round((Math.abs(item.impact) / maxAbsImpact) * 100);

            return (
              <div
                key={idx}
                className="p-3.5 rounded-[8px] bg-[#F6F8FB] dark:bg-[#161E2E] border border-[#E2E8F0] dark:border-slate-800 space-y-2 transition-colors hover:border-slate-300 dark:hover:border-slate-700"
              >
                {/* Title & Badge */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 text-xs font-mono">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-[#0F172A] dark:text-white">
                      {item.feature}
                    </span>
                    <span className="text-[10px] text-slate-400 dark:text-slate-500 font-normal">
                      ({item.category})
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <span
                      className={`text-xs font-bold font-mono px-2 py-0.5 rounded-[4px] ${
                        isPos
                          ? 'bg-rose-50 dark:bg-rose-950/40 text-[#DC2626] dark:text-rose-400 border border-rose-200 dark:border-rose-900/50'
                          : 'bg-emerald-50 dark:bg-emerald-950/40 text-[#059669] dark:text-emerald-400 border border-emerald-200 dark:border-emerald-900/50'
                      }`}
                    >
                      {isPos ? `+${item.impact.toFixed(2)}` : item.impact.toFixed(2)}
                    </span>
                    <span className="text-[10px] text-[#64748B] dark:text-slate-400 font-medium hidden sm:inline">
                      {isPos ? 'Increases Vulnerability' : 'Protective Factor'}
                    </span>
                  </div>
                </div>

                {/* Relative Horizontal Bar */}
                <div className="w-full bg-slate-200/80 dark:bg-slate-800 rounded-full h-2 overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all duration-500 ${
                      isPos ? 'bg-[#DC2626]' : 'bg-[#059669]'
                    }`}
                    style={{ width: `${widthPct}%` }}
                  />
                </div>

                {/* Technical Explanation */}
                <p className="text-[11px] text-[#64748B] dark:text-slate-400 font-sans leading-tight">
                  {item.explanation}
                </p>
              </div>
            );
          })}
        </div>

        {/* Technical Formulation Footer */}
        <div className="p-3.5 rounded-[8px] bg-white dark:bg-[#111827] border border-[#E2E8F0] dark:border-slate-800 text-xs font-mono space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-bold uppercase tracking-wider text-[#0F172A] dark:text-white flex items-center gap-1.5">
              <Info className="w-3.5 h-3.5 text-[#4F46E5] dark:text-indigo-400" />
              <span>Tree SHAP Exact Attribution Mechanism</span>
            </span>
            <button
              onClick={() => setShowFormula(!showFormula)}
              className="text-[11px] text-[#4F46E5] dark:text-indigo-400 hover:underline cursor-pointer"
            >
              {showFormula ? 'Hide Formulation' : 'View Mathematical Formulation'}
            </button>
          </div>

          <p className="text-[11px] text-[#64748B] dark:text-slate-400 font-sans leading-relaxed">
            Tree SHAP computes exact Shapley values across the ensemble trees in polynomial time <span className="font-mono font-semibold">O(TLD²)</span>. Rather than treating XGBoost as an uninterpretable black box, each detected cryptographic parameter receives an additive credit score that directly explains the vulnerability risk rating.
          </p>

          {showFormula && (
            <div className="p-3 bg-[#0F172A] text-slate-100 rounded-[6px] text-[11px] font-mono overflow-x-auto border border-slate-800 space-y-1">
              <div className="text-indigo-400 font-bold">SHAP Additive Explanation Model:</div>
              <div>g(z') = φ₀ + Σ φᵢ · z'ᵢ</div>
              <div className="text-slate-400 text-[10px] pt-1">
                Where <span className="text-slate-200">φ₀ = 0.50</span> is the expected base model output, <span className="text-slate-200">φᵢ</span> represents feature Shapley contribution, and <span className="text-slate-200">g(z')</span> matches the actual model output <span className="text-slate-200">f(x)</span>.
              </div>
            </div>
          )}
        </div>

      </div>

    </section>
  );
}
