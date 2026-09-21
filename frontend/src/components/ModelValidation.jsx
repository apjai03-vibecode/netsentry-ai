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
              109 validation sessions
            </span>
          </div>
          <p className="text-[11px] text-[#64748B] font-mono">
            Dual-engine validation using supervised XGBoost and unsupervised Isolation Forest with Tree SHAP explainability.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-[11px] font-mono text-slate-600 bg-white px-2.5 py-1 rounded-[6px] border border-[#E2E8F0]">
            Validated on 109 out-of-sample sessions
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
                <span>Confusion Matrix</span>
              </span>
              <span className="text-[10px] font-mono text-[#64748B] font-semibold">
                109 validation sessions
              </span>
            </div>

            {/* Matrix Grid matching exact layout */}
            <div className="overflow-x-auto border border-[#E2E8F0] rounded-[6px] bg-white">
              <table className="w-full text-xs font-mono border-collapse">
                <thead>
                  {/* Top Level: Predicted Header */}
                  <tr className="border-b border-[#E2E8F0] bg-slate-50/70 text-[#64748B] text-[10px] uppercase">
                    <th className="py-1 px-3 text-left border-r border-[#E2E8F0]"></th>
                    <th colSpan="2" className="py-1 px-3 text-center font-bold text-[#0F172A] tracking-wider">
                      Predicted
                    </th>
                  </tr>
                  {/* Sub Header: Secure vs Vulnerable */}
                  <tr className="border-b border-[#E2E8F0] bg-slate-50/40 text-[#64748B] text-[10px] uppercase">
                    <th className="py-2 px-3 text-left font-semibold border-r border-[#E2E8F0]">Actual</th>
                    <th className="py-2 px-3 text-center font-semibold text-[#059669]">
                      Secure
                    </th>
                    <th className="py-2 px-3 text-center font-semibold text-[#DC2626]">
                      Vulnerable
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#E2E8F0]">
                  {/* Row 1: Actual Secure */}
                  <tr>
                    <td className="py-2.5 px-3 font-semibold text-[#0F172A] text-[11px] border-r border-[#E2E8F0] bg-slate-50/30">
                      Actual Secure
                    </td>
                    <td className="py-2.5 px-3 text-center bg-emerald-50/30">
                      <div className="font-extrabold text-[#059669] text-base">54</div>
                      <div className="text-[9px] text-[#059669] uppercase font-bold tracking-tight">54 True Negatives (TN)</div>
                    </td>
                    <td className="py-2.5 px-3 text-center">
                      <div className="font-extrabold text-[#0F172A] text-base">0</div>
                      <div className="text-[9px] text-slate-400 uppercase tracking-tight">0 False Positives (FP)</div>
                    </td>
                  </tr>

                  {/* Row 2: Actual Vulnerable */}
                  <tr>
                    <td className="py-2.5 px-3 font-semibold text-[#0F172A] text-[11px] border-r border-[#E2E8F0] bg-slate-50/30">
                      Actual Vulnerable
                    </td>
                    <td className="py-2.5 px-3 text-center">
                      <div className="font-extrabold text-[#0F172A] text-base">0</div>
                      <div className="text-[9px] text-slate-400 uppercase tracking-tight">0 False Negatives (FN)</div>
                    </td>
                    <td className="py-2.5 px-3 text-center bg-rose-50/30">
                      <div className="font-extrabold text-[#DC2626] text-base">55</div>
                      <div className="text-[9px] text-[#DC2626] uppercase font-bold tracking-tight">55 True Positives (TP)</div>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>

            <div className="mt-3 pt-2 border-t border-[#E2E8F0] flex items-center justify-between text-[10px] font-mono text-[#64748B]">
              <span>Type I Error (False Positive): 0.0%</span>
              <span>Type II Error (False Negative): 0.0%</span>
            </div>
          </div>

          {/* Model Specification & Architecture Notes (5 Cols) */}
          <div className="lg:col-span-5 bg-white border border-[#E2E8F0] rounded-[8px] p-4 space-y-3 text-xs font-mono">
            <span className="text-xs font-mono font-bold uppercase tracking-wider text-[#0F172A] block">
              Validation Protocol Notes
            </span>

            <div className="space-y-2 text-[11px]">
              <div className="p-2.5 rounded-[6px] bg-[#F6F8FB] border border-[#E2E8F0]">
                <div className="text-[#0F172A] font-bold">Dual-Engine Verification</div>
                <div className="text-[#64748B] text-[10px] mt-0.5">
                  Supervised XGBoost and unsupervised Isolation Forest cross-validate findings to prevent single-model bias.
                </div>
              </div>

              <div className="p-2.5 rounded-[6px] bg-[#F6F8FB] border border-[#E2E8F0]">
                <div className="text-[#0F172A] font-bold">Zero False Alarms (0.0% FPR)</div>
                <div className="text-[#64748B] text-[10px] mt-0.5">
                  All 54 RFC-compliant control sessions correctly classified without triggering false positive alerts.
                </div>
              </div>

              <div className="p-2.5 rounded-[6px] bg-[#F6F8FB] border border-[#E2E8F0]">
                <div className="text-[#0F172A] font-bold">Out-of-Sample Calibration</div>
                <div className="text-[#64748B] text-[10px] mt-0.5">
                  Evaluated on 109 testbed handshakes spanning IKEv1 Aggressive, Main Mode, and IKEv2 proposals.
                </div>
              </div>
            </div>
          </div>

        </div>

      </div>

    </section>
  );
}
