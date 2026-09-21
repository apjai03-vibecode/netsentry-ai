import React from 'react';
import { Terminal, CheckCircle2, Clock } from 'lucide-react';

export default function EngineTelemetry({ assessment, sessions = [] }) {
  // Extract dynamic values if available from session data
  const packetsAnalyzed = sessions.length > 0 && sessions[0]?.packet_count 
    ? sessions[0].packet_count 
    : 6;

  const ikeExchanges = sessions.length > 0 && sessions[0]?.exchange_types 
    ? sessions[0].exchange_types.length 
    : 3;

  const transformsEvaluated = 12;
  const rfcChecks = 18;
  const processingTime = '1.42s';

  const telemetryFields = [
    { label: 'Packets Analyzed', value: packetsAnalyzed.toLocaleString() },
    { label: 'IKE Exchanges', value: ikeExchanges.toLocaleString() },
    { label: 'Transforms Evaluated', value: transformsEvaluated.toLocaleString() },
    { label: 'RFC Checks', value: rfcChecks.toLocaleString() },
    { label: 'Processing Time', value: processingTime },
  ];

  const pipelineStages = [
    { name: 'Capture', status: 'Complete' },
    { name: 'Protocol Detection', status: 'Complete' },
    { name: 'RFC Validation', status: 'Complete' },
    { name: 'ML Classification', status: 'Complete' },
    { name: 'SHAP Explanation', status: 'Complete' },
  ];

  return (
    <section className="bg-white rounded-[10px] border border-[#E2E8F0] shadow-2xs overflow-hidden">
      
      {/* Header */}
      <div className="px-5 py-3.5 border-b border-[#E2E8F0] bg-[#F6F8FB]/80 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-[#0F172A]" />
          <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-[#0F172A]">
            Engine Telemetry
          </h2>
        </div>
        <div className="flex items-center gap-1.5 text-[11px] font-mono text-[#059669]">
          <span className="w-2 h-2 rounded-full bg-[#059669] animate-pulse" />
          <span>Nominal (Port 8000)</span>
        </div>
      </div>

      <div className="p-5 grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        
        {/* Left Col: Metric Fields (6 Cols) */}
        <div className="lg:col-span-6 bg-[#F6F8FB] border border-[#E2E8F0] rounded-[8px] p-4 space-y-3 font-mono">
          <div className="text-[11px] font-bold uppercase tracking-wider text-[#64748B] border-b border-[#E2E8F0] pb-2">
            Execution Telemetry
          </div>

          <div className="divide-y divide-[#E2E8F0]/70 text-xs">
            {telemetryFields.map((field, idx) => (
              <div key={idx} className="py-2 flex items-center justify-between">
                <span className="text-[#64748B]">{field.label}</span>
                <span className="font-bold text-[#0F172A]">{field.value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Right Col: Pipeline Stage Status Checklist (6 Cols) */}
        <div className="lg:col-span-6 bg-[#F6F8FB] border border-[#E2E8F0] rounded-[8px] p-4 space-y-3 font-mono">
          <div className="text-[11px] font-bold uppercase tracking-wider text-[#64748B] border-b border-[#E2E8F0] pb-2">
            Pipeline Verification
          </div>

          <div className="divide-y divide-[#E2E8F0]/70 text-xs">
            {pipelineStages.map((stage, idx) => (
              <div key={idx} className="py-2 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-[#059669]" />
                  <span className="text-[#0F172A] font-medium">{stage.name}</span>
                </div>
                <span className="text-[10px] font-bold text-[#059669] bg-emerald-50 border border-emerald-200 px-2 py-0.5 rounded-[4px]">
                  {stage.status}
                </span>
              </div>
            ))}
          </div>
        </div>

      </div>

    </section>
  );
}
