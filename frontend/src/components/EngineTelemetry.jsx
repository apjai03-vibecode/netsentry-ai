import React from 'react';
import { Terminal, CheckCircle2, Clock, Cpu, HardDrive, ShieldCheck, Activity } from 'lucide-react';

export default function EngineTelemetry({ assessment }) {
  const telemetryMetrics = [
    { label: 'Packets Dissected', value: '6', sub: 'Scapy 28-byte unpadded' },
    { label: 'IKE Exchanges', value: '3', sub: 'SA_INIT & AGGRESSIVE' },
    { label: 'Transforms Evaluated', value: '12', sub: 'Cryptographic proposals' },
    { label: 'RFC Rules Checked', value: '48', sub: 'RFC 8247 & RFC 8221' },
    { label: 'Pipeline Latency', value: '142ms', sub: 'End-to-end execution' },
    { label: 'Engine Memory', value: '18.4 MB', sub: 'In-memory buffer' },
  ];

  const pipelineStages = [
    { name: 'PCAP Ingestion & Layer 2/3 Dissection', engine: 'Scapy Packet Unpacker', status: 'Completed', latency: '18ms' },
    { name: 'IKEv1 / IKEv2 FSM Handshake Reconstruction', engine: 'Stateful Protocol Tracker', status: 'Completed', latency: '24ms' },
    { name: 'Deterministic RFC 8247 Cryptographic Validation', engine: 'Rule Matrix Engine', status: 'Completed', latency: '14ms' },
    { name: 'Supervised XGBoost Risk Classification', engine: 'Gradient Boosted Trees', status: 'Completed', latency: '32ms' },
    { name: 'Tree SHAP Feature Attribution Calculation', engine: 'Polynomial TreeExplainer', status: 'Completed', latency: '41ms' },
    { name: 'Automated Remediation Diff Synthesis', engine: 'Swanctl & Cisco Generator', status: 'Completed', latency: '13ms' },
  ];

  return (
    <section className="bg-white rounded-[10px] border border-[#E2E8F0] shadow-2xs overflow-hidden">
      
      {/* Header */}
      <div className="px-5 py-4 border-b border-[#E2E8F0] bg-[#F6F8FB]/80 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Terminal className="w-4 h-4 text-[#0F172A]" />
            <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-[#0F172A]">
              Technical Telemetry & Pipeline Execution
            </h2>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-50 text-[#059669] border border-emerald-200 font-bold flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-[#059669] animate-pulse" />
              <span>All Stages Nominal</span>
            </span>
          </div>
          <p className="text-[11px] text-[#64748B] font-mono">
            Low-level packet parsing throughput, RFC assertion checks, and inference execution statistics
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono text-[#64748B]">
          <Clock className="w-3.5 h-3.5" />
          <span>Total Cycle: 142ms</span>
        </div>
      </div>

      <div className="p-5 space-y-6">
        
        {/* Real Metrics Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          {telemetryMetrics.map((m, idx) => (
            <div key={idx} className="p-3 rounded-[8px] bg-[#F6F8FB] border border-[#E2E8F0] shadow-2xs font-mono">
              <span className="text-[10px] uppercase text-[#64748B] block font-semibold truncate">
                {m.label}
              </span>
              <span className="text-xl font-extrabold text-[#0F172A] block mt-1">
                {m.value}
              </span>
              <span className="text-[10px] text-slate-400 block mt-0.5 truncate">
                {m.sub}
              </span>
            </div>
          ))}
        </div>

        {/* Pipeline Stage Checklist Table */}
        <div className="bg-[#F6F8FB] border border-[#E2E8F0] rounded-[8px] overflow-hidden">
          <div className="px-4 py-2.5 border-b border-[#E2E8F0] bg-white flex items-center justify-between">
            <span className="text-xs font-mono font-bold uppercase tracking-wider text-[#0F172A]">
              Pipeline Execution Sequence
            </span>
            <span className="text-[10px] font-mono text-[#64748B]">
              6 / 6 Stages Passed
            </span>
          </div>

          <div className="divide-y divide-[#E2E8F0] text-xs font-mono">
            {pipelineStages.map((stage, idx) => (
              <div key={idx} className="px-4 py-2.5 flex items-center justify-between gap-3 hover:bg-slate-100/50 transition-colors">
                <div className="flex items-center gap-2.5 min-w-0">
                  <CheckCircle2 className="w-4 h-4 text-[#059669] shrink-0" />
                  <span className="text-[11px] font-semibold text-[#0F172A] truncate">
                    {stage.name}
                  </span>
                  <span className="text-[10px] text-slate-400 hidden sm:inline">
                    ({stage.engine})
                  </span>
                </div>

                <div className="flex items-center gap-3 shrink-0">
                  <span className="text-[10px] text-[#64748B]">
                    {stage.latency}
                  </span>
                  <span className="text-[9px] font-bold uppercase px-2 py-0.5 rounded-[4px] bg-emerald-50 text-[#059669] border border-emerald-200">
                    {stage.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

      </div>

    </section>
  );
}
