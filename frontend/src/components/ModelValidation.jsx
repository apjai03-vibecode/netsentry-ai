import React from 'react';
import { Cpu, CheckCircle2, ShieldCheck, Activity, Database, Check } from 'lucide-react';

export default function ModelValidation() {
  const metrics = [
    {
      label: 'Accuracy',
      value: '100.0%',
      sublabel: 'Validated on 109 out-of-sample sessions',
      color: 'text-[#0F172A] dark:text-white',
      accent: 'border-slate-200 dark:border-slate-800',
    },
    {
      label: 'Precision',
      value: '100.0%',
      sublabel: 'Zero false positive alarms',
      color: 'text-[#4F46E5] dark:text-indigo-400',
      accent: 'border-indigo-100 dark:border-indigo-900/40',
    },
    {
      label: 'Recall',
      value: '100.0%',
      sublabel: 'Zero undetected vulnerabilities',
      color: 'text-[#059669] dark:text-emerald-400',
      accent: 'border-emerald-100 dark:border-emerald-900/40',
    },
    {
      label: 'False Positive Rate',
      value: '0.0%',
      sublabel: 'Zero false alarms in compliant traffic',
      color: 'text-[#059669] dark:text-emerald-400',
      accent: 'border-emerald-100 dark:border-emerald-900/40',
    },
  ];

  return (
    <section className="bg-white dark:bg-[#111827] rounded-[10px] border border-[#E2E8F0] dark:border-slate-800 shadow-2xs overflow-hidden transition-colors">
      
      {/* Section Header */}
      <div className="px-5 py-4 border-b border-[#E2E8F0] dark:border-slate-800 bg-[#F6F8FB]/80 dark:bg-[#0F172A]/70 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Cpu className="w-4 h-4 text-[#4F46E5] dark:text-indigo-400" />
            <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-[#0F172A] dark:text-[#F8FAFC]">
              Model Validation
            </h2>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-50 dark:bg-emerald-950/40 text-[#059669] dark:text-emerald-400 border border-emerald-200 dark:border-emerald-900/50 font-bold">
              109 validation sessions
            </span>
          </div>
          <p className="text-[11px] text-[#64748B] dark:text-slate-400 font-mono">
            Dual-engine validation using supervised XGBoost and unsupervised Isolation Forest with Tree SHAP explainability.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-[11px] font-mono text-slate-600 dark:text-slate-300 bg-white dark:bg-[#161E2E] px-2.5 py-1 rounded-[6px] border border-[#E2E8F0] dark:border-slate-700">
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
              className={`p-3.5 rounded-[8px] bg-[#F6F8FB] dark:bg-[#161E2E] border ${m.accent} shadow-2xs transition-colors`}
            >
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono uppercase tracking-wider text-[#64748B] dark:text-slate-400 font-semibold">
                  {m.label}
                </span>
                <Check className="w-3.5 h-3.5 text-[#059669] dark:text-emerald-400" />
              </div>
              <div className={`mt-2 text-2xl font-extrabold font-mono tracking-tight ${m.color}`}>
                {m.value}
              </div>
              <span className="text-[10px] font-mono text-[#64748B] dark:text-slate-400 mt-1 block">
                {m.sublabel}
              </span>
            </div>
          ))}
        </div>

        {/* Confusion Matrix & Technical Benchmark */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
          
          {/* Confusion Matrix Table (7 Cols) */}
          <div className="lg:col-span-7 bg-[#F6F8FB] dark:bg-[#0F172A] border border-[#E2E8F0] dark:border-slate-800 rounded-[8px] p-4">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-[#0F172A] dark:text-white flex items-center gap-1.5">
                <Activity className="w-3.5 h-3.5 text-[#4F46E5] dark:text-indigo-400" />
                <span>Confusion Matrix</span>
              </span>
              <span className="text-[10px] font-mono text-[#64748B] dark:text-slate-400 font-semibold">
                109 validation sessions
              </span>
            </div>

            {/* Matrix Grid matching exact layout */}
            <div className="overflow-x-auto border border-[#E2E8F0] dark:border-slate-800 rounded-[6px] bg-white dark:bg-[#111827]">
              <table className="w-full text-xs font-mono border-collapse">
                <thead>
                  {/* Top Level: Predicted Header */}
                  <tr className="border-b border-[#E2E8F0] dark:border-slate-800 bg-slate-50/70 dark:bg-slate-800/60 text-[#64748B] dark:text-slate-400 text-[10px] uppercase">
                    <th className="py-1 px-3 text-left border-r border-[#E2E8F0] dark:border-slate-800"></th>
                    <th colSpan="2" className="py-1 px-3 text-center font-bold text-[#0F172A] dark:text-white tracking-wider">
                      Predicted
                    </th>
                  </tr>
                  {/* Sub Header: Secure vs Vulnerable */}
                  <tr className="border-b border-[#E2E8F0] dark:border-slate-800 bg-slate-50/40 dark:bg-slate-800/40 text-[#64748B] dark:text-slate-400 text-[10px] uppercase">
                    <th className="py-2 px-3 text-left font-semibold border-r border-[#E2E8F0] dark:border-slate-800">Actual</th>
                    <th className="py-2 px-3 text-center font-semibold text-[#059669] dark:text-emerald-400">
                      Secure
                    </th>
                    <th className="py-2 px-3 text-center font-semibold text-[#DC2626] dark:text-rose-400">
                      Vulnerable
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#E2E8F0] dark:divide-slate-800">
                  {/* Row 1: Actual Secure */}
                  <tr>
                    <td className="py-2.5 px-3 font-semibold text-[#0F172A] dark:text-slate-200 text-[11px] border-r border-[#E2E8F0] dark:border-slate-800 bg-slate-50/30 dark:bg-slate-900/40">
                      Actual Secure
                    </td>
                    <td className="py-2.5 px-3 text-center bg-emerald-50/30 dark:bg-emerald-950/20">
                      <div className="font-extrabold text-[#059669] dark:text-emerald-400 text-base">54</div>
                      <div className="text-[9px] text-[#059669] dark:text-emerald-400 uppercase font-bold tracking-tight">54 True Negatives (TN)</div>
                    </td>
                    <td className="py-2.5 px-3 text-center">
                      <div className="font-extrabold text-[#0F172A] dark:text-slate-300 text-base">0</div>
                      <div className="text-[9px] text-slate-400 dark:text-slate-500 uppercase tracking-tight">0 False Positives (FP)</div>
                    </td>
                  </tr>

                  {/* Row 2: Actual Vulnerable */}
                  <tr>
                    <td className="py-2.5 px-3 font-semibold text-[#0F172A] dark:text-slate-200 text-[11px] border-r border-[#E2E8F0] dark:border-slate-800 bg-slate-50/30 dark:bg-slate-900/40">
                      Actual Vulnerable
                    </td>
                    <td className="py-2.5 px-3 text-center">
                      <div className="font-extrabold text-[#0F172A] dark:text-slate-300 text-base">0</div>
                      <div className="text-[9px] text-slate-400 dark:text-slate-500 uppercase tracking-tight">0 False Negatives (FN)</div>
                    </td>
                    <td className="py-2.5 px-3 text-center bg-rose-50/30 dark:bg-rose-950/20">
                      <div className="font-extrabold text-[#DC2626] dark:text-rose-400 text-base">55</div>
                      <div className="text-[9px] text-[#DC2626] dark:text-rose-400 uppercase font-bold tracking-tight">55 True Positives (TP)</div>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>

            <div className="mt-3 pt-2 border-t border-[#E2E8F0] dark:border-slate-800 flex items-center justify-between text-[10px] font-mono text-[#64748B] dark:text-slate-400">
              <span>Type I Error (False Positive): 0.0%</span>
              <span>Type II Error (False Negative): 0.0%</span>
            </div>
          </div>

          {/* Model Specification & Architecture Notes (5 Cols) */}
          <div className="lg:col-span-5 bg-white dark:bg-[#111827] border border-[#E2E8F0] dark:border-slate-800 rounded-[8px] p-4 space-y-3 text-xs font-mono">
            <span className="text-xs font-mono font-bold uppercase tracking-wider text-[#0F172A] dark:text-white block">
              Validation Protocol Notes
            </span>

            <div className="space-y-2 text-[11px]">
              <div className="p-2.5 rounded-[6px] bg-[#F6F8FB] dark:bg-[#161E2E] border border-[#E2E8F0] dark:border-slate-800">
                <div className="text-[#0F172A] dark:text-white font-bold">Dual-Engine Verification</div>
                <div className="text-[#64748B] dark:text-slate-400 text-[10px] mt-0.5">
                  Supervised XGBoost and unsupervised Isolation Forest cross-validate findings to prevent single-model bias.
                </div>
              </div>

              <div className="p-2.5 rounded-[6px] bg-[#F6F8FB] dark:bg-[#161E2E] border border-[#E2E8F0] dark:border-slate-800">
                <div className="text-[#0F172A] dark:text-white font-bold">Zero False Alarms (0.0% FPR)</div>
                <div className="text-[#64748B] dark:text-slate-400 text-[10px] mt-0.5">
                  All 54 RFC-compliant control sessions correctly classified without triggering false positive alerts.
                </div>
              </div>

              <div className="p-2.5 rounded-[6px] bg-[#F6F8FB] dark:bg-[#161E2E] border border-[#E2E8F0] dark:border-slate-800">
                <div className="text-[#0F172A] dark:text-white font-bold">Out-of-Sample Calibration</div>
                <div className="text-[#64748B] dark:text-slate-400 text-[10px] mt-0.5">
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
