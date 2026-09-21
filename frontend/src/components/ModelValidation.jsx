import React from 'react';
import { Cpu, CheckCircle2, ShieldCheck, Activity, Database, Check } from 'lucide-react';

export default function ModelValidation() {
  const metrics = [
    {
      label: 'Accuracy',
      value: '100.0%',
      sublabel: 'Validated on 109 out-of-sample sessions',
      color: 'text-[#0F172A]',
      accent: 'border-slate-200',
    },
    {
      label: 'Precision',
      value: '100.0%',
      sublabel: 'Zero false positive alarms',
      color: 'text-[#4F46E5]',
      accent: 'border-indigo-100',
    },
    {
      label: 'Recall',
      value: '100.0%',
      sublabel: 'Zero undetected vulnerabilities',
      color: 'text-[#059669]',
      accent: 'border-emerald-100',
    },
    {
      label: 'False Positive Rate',
      value: '0.0%',
      sublabel: 'Zero false alarms in compliant traffic',
      color: 'text-[#059669]',
      accent: 'border-emerald-100',
    },
  ];

  return (
    <section className="bg-white rounded-[10px] border border-[#E2E8F0] shadow-2xs overflow-hidden">
      
      {/* Section Header */}
      <div className="px-5 py-4 border-b border-[#E2E8F0] bg-[#F6F8FB]/80 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Cpu className="w-4 h-4 text-[#4F46E5]" />
            <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-[#0F172A]">
              Model Validation
            </h2>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-50 text-[#059669] border border-emerald-200 font-bold">
              109 Sessions Evaluated
            </span>
          </div>
          <p className="text-[11px] text-[#64748B] font-mono">
            Dual-engine validation using supervised XGBoost and unsupervised Isolation Forest with Tree SHAP explainability
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-[11px] font-mono text-slate-500 bg-white px-2.5 py-1 rounded-[6px] border border-[#E2E8F0]">
            Dual Engine: XGBoost + Isolation Forest
          </span>
        </div>
      </div>

      <div className="p-5 space-y-6">
        
        {/* 4 Metric Cards Grid */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          {metrics.map((m, idx) => (
            <div
              key={idx}
              className={`p-3.5 rounded-[8px] bg-[#F6F8FB] border ${m.accent} shadow-2xs`}
            >
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono uppercase tracking-wider text-[#64748B] font-semibold">
                  {m.label}
                </span>
                <Check className="w-3.5 h-3.5 text-[#059669]" />
              </div>
              <div className={`mt-2 text-2xl font-extrabold font-mono tracking-tight ${m.color}`}>
                {m.value}
              </div>
              <span className="text-[10px] font-mono text-[#64748B] mt-1 block">
                {m.sublabel}
              </span>
            </div>
          ))}
        </div>

        {/* Confusion Matrix & Technical Benchmark */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
          
          {/* Confusion Matrix Table (7 Cols) */}
          <div className="lg:col-span-7 bg-[#F6F8FB] border border-[#E2E8F0] rounded-[8px] p-4">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-[#0F172A] flex items-center gap-1.5">
                <Activity className="w-3.5 h-3.5 text-[#4F46E5]" />
                <span>Testbed Confusion Matrix</span>
              </span>
              <span className="text-[10px] font-mono text-[#64748B]">
                N = 109 PCAP Handshakes
              </span>
            </div>

            {/* Matrix Grid */}
            <div className="overflow-x-auto">
              <table className="w-full text-xs font-mono border-collapse">
                <thead>
                  <tr className="border-b border-[#E2E8F0] text-[#64748B] text-[10px] uppercase">
                    <th className="py-2 px-3 text-left font-semibold">Ground Truth</th>
                    <th className="py-2 px-3 text-center font-semibold bg-emerald-50/50 rounded-t-[6px]">
                      Predicted Compliant
                    </th>
                    <th className="py-2 px-3 text-center font-semibold bg-rose-50/50 rounded-t-[6px]">
                      Predicted Vulnerable
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#E2E8F0]">
                  {/* Row 1: Actual Compliant */}
                  <tr>
                    <td className="py-2.5 px-3 font-semibold text-[#0F172A] text-[11px]">
                      Actual Compliant <span className="text-slate-400 font-normal">(54)</span>
                    </td>
                    <td className="py-2.5 px-3 text-center bg-white">
                      <div className="font-extrabold text-[#059669] text-sm">54</div>
                      <div className="text-[9px] text-[#059669] uppercase font-bold">TN (100%)</div>
                    </td>
                    <td className="py-2.5 px-3 text-center bg-white">
                      <div className="font-extrabold text-[#0F172A] text-sm">0</div>
                      <div className="text-[9px] text-slate-400 uppercase">FP (0.0%)</div>
                    </td>
                  </tr>

                  {/* Row 2: Actual Vulnerable */}
                  <tr>
                    <td className="py-2.5 px-3 font-semibold text-[#0F172A] text-[11px]">
                      Actual Vulnerable <span className="text-slate-400 font-normal">(55)</span>
                    </td>
                    <td className="py-2.5 px-3 text-center bg-white">
                      <div className="font-extrabold text-[#0F172A] text-sm">0</div>
                      <div className="text-[9px] text-slate-400 uppercase">FN (0.0%)</div>
                    </td>
                    <td className="py-2.5 px-3 text-center bg-white">
                      <div className="font-extrabold text-[#DC2626] text-sm">55</div>
                      <div className="text-[9px] text-[#DC2626] uppercase font-bold">TP (100%)</div>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>

            <div className="mt-3 pt-2.5 border-t border-[#E2E8F0] flex items-center justify-between text-[10px] font-mono text-[#64748B]">
              <span>Type I Error (False Positive): 0.0%</span>
              <span>Type II Error (False Negative): 0.0%</span>
            </div>
          </div>

          {/* Model Specification & Architecture Notes (5 Cols) */}
          <div className="lg:col-span-5 bg-white border border-[#E2E8F0] rounded-[8px] p-4 space-y-3 text-xs font-mono">
            <span className="text-xs font-mono font-bold uppercase tracking-wider text-[#0F172A] block">
              Ensemble Architecture
            </span>

            <div className="space-y-2 text-[11px]">
              <div className="p-2.5 rounded-[6px] bg-[#F6F8FB] border border-[#E2E8F0]">
                <div className="text-[#0F172A] font-bold">Supervised Engine: XGBoost</div>
                <div className="text-[#64748B] text-[10px] mt-0.5">
                  Gradient boosted decision trees trained on multi-attribute cryptographic vectors (DH Group, Cipher, MAC, PRF, PFS, Exchange Mode).
                </div>
              </div>

              <div className="p-2.5 rounded-[6px] bg-[#F6F8FB] border border-[#E2E8F0]">
                <div className="text-[#0F172A] font-bold">Unsupervised Engine: Isolation Forest</div>
                <div className="text-[#64748B] text-[10px] mt-0.5">
                  Anomaly isolation score detector identifying novel or non-standard protocol permutations and malformed payloads.
                </div>
              </div>

              <div className="p-2.5 rounded-[6px] bg-[#F6F8FB] border border-[#E2E8F0]">
                <div className="text-[#0F172A] font-bold">Explainability: Tree SHAP</div>
                <div className="text-[#64748B] text-[10px] mt-0.5">
                  Local and global Shapley values calculate exact per-feature risk impact and protective weights.
                </div>
              </div>
            </div>
          </div>

        </div>

      </div>

    </section>
  );
}
