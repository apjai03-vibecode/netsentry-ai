import React, { useState } from 'react';
import { Layers, Eye, ShieldCheck, ShieldAlert, Lock, Unlock } from 'lucide-react';

export default function SessionInspector({ assessment, findings = [] }) {
  const [selectedPacket, setSelectedPacket] = useState(0);

  const packets = [
    {
      seq: 1,
      direction: 'Initiator ➔ Responder',
      src: '192.168.1.100:500',
      dst: '198.51.100.1:500',
      exchange: 'IKE_SA_INIT (Type: 34 / Aggressive: 4)',
      msgId: '0x00000000',
      spi_i: '0x1122334455667788',
      spi_r: '0x0000000000000000',
      observability: 'OBSERVED',
      observabilityReason: 'Direct cleartext wire headers and transform proposal bytes per RFC 7296',
      payloads: [
        { name: 'Security Association (SA)', obs: 'OBSERVED' },
        { name: 'Key Exchange (KE: DH Group 2)', obs: 'OBSERVED' },
        { name: 'Nonce (Ni)', obs: 'OBSERVED' },
        { name: 'Identification (IDi)', obs: 'OBSERVED' },
      ],
      flags: 'Initiator (0x08)',
      status: 'warning',
      notes: 'Contains Proposal #1: ENCR=3DES-CBC, HASH=MD5, DH=Group 2 (1024-bit MODP). Initiator ID transmitted prior to encryption in Aggressive Mode.',
    },
    {
      seq: 2,
      direction: 'Responder ➔ Initiator',
      src: '198.51.100.1:500',
      dst: '192.168.1.100:500',
      exchange: 'IKE_SA_INIT / AGGRESSIVE_RESP',
      msgId: '0x00000000',
      spi_i: '0x1122334455667788',
      spi_r: '0x99aabbccddeeff00',
      observability: 'OBSERVED',
      observabilityReason: 'Direct cleartext transform acceptance and public Diffie-Hellman value',
      payloads: [
        { name: 'SA (Accepted Prop #1)', obs: 'OBSERVED' },
        { name: 'Key Exchange (KE: DH Group 2)', obs: 'OBSERVED' },
        { name: 'Nonce (Nr)', obs: 'OBSERVED' },
        { name: 'Identification (IDr)', obs: 'OBSERVED' },
        { name: 'HASH(r)', obs: 'OBSERVED' },
      ],
      flags: 'Response (0x20)',
      status: 'warning',
      notes: 'Responder accepts deprecated 3DES-CBC and weak MODP-1024. Computes public Diffie-Hellman value.',
    },
    {
      seq: 3,
      direction: 'Initiator ➔ Responder',
      src: '192.168.1.100:500',
      dst: '198.51.100.1:500',
      exchange: 'IKE_AUTH / AGGRESSIVE_CONFIRM',
      msgId: '0x00000001',
      spi_i: '0x1122334455667788',
      spi_r: '0x99aabbccddeeff00',
      observability: 'OBSERVED',
      observabilityReason: 'Cleartext authentication hash transmitted on wire without secure channel',
      payloads: [
        { name: 'HASH(i) [Pre-Shared Key Hash]', obs: 'OBSERVED' },
        { name: 'Child SA Proposals', obs: 'NOT_OBSERVABLE' },
      ],
      flags: 'Initiator (0x08)',
      status: 'danger',
      notes: 'CRITICAL: Transmits cleartext PSK authentication hash. Offline dictionary attack allows recovery of the pre-shared secret.',
    },
    {
      seq: 4,
      direction: 'Bidirectional Tunnel',
      src: '192.168.1.100',
      dst: '198.51.100.1',
      exchange: 'IPsec ESP (Protocol 50 Data Traffic)',
      msgId: 'Sequence 1..1042',
      spi_i: '0x3a4b5c6d',
      spi_r: '0x7e8f9a0b',
      observability: 'INFERRED',
      observabilityReason: 'Tunnel Mode vs Transport Mode inferred from outer MTU; payload plaintext NOT OBSERVABLE',
      payloads: [
        { name: 'Outer IP Header & SPI', obs: 'OBSERVED' },
        { name: 'ESP Sequence Number', obs: 'OBSERVED' },
        { name: 'Traffic Profile / App Class', obs: 'INFERRED' },
        { name: 'Payload Plaintext & Inner IPs', obs: 'NOT_OBSERVABLE' },
      ],
      flags: 'Encrypted',
      status: 'warning',
      notes: 'Child SA active with 3DES-CBC. Subject to Sweet32 collision attacks after 32GB of data.',
    },
  ];

  const getObservabilityBadge = (obs) => {
    switch (obs) {
      case 'OBSERVED':
        return 'bg-teal-500/10 text-teal-700 dark:text-teal-300 border-teal-500/30';
      case 'INFERRED':
        return 'bg-purple-500/10 text-purple-700 dark:text-purple-300 border-purple-500/30';
      default:
        return 'bg-slate-500/10 text-slate-700 dark:text-slate-400 border-slate-500/30';
    }
  };

  return (
    <div className="bg-white dark:bg-[#111827] rounded-[10px] border border-[#E2E8F0] dark:border-slate-800 shadow-2xs overflow-hidden transition-colors">
      
      {/* Header */}
      <div className="px-5 py-3.5 border-b border-[#E2E8F0] dark:border-slate-800 bg-[#F6F8FB]/80 dark:bg-[#0F172A]/70 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Layers className="w-4 h-4 text-[#4F46E5] dark:text-indigo-400" />
          <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-[#0F172A] dark:text-[#F8FAFC]">
            Handshake State & Packet Sequence Inspector
          </h3>
        </div>
        
        {/* Observability Taxonomy Legend */}
        <div className="flex items-center gap-1.5 text-[10px] font-mono">
          <span className="px-1.5 py-0.5 rounded border bg-teal-500/10 text-teal-700 dark:text-teal-300 border-teal-500/30 font-bold">
            [OBSERVED] Wire
          </span>
          <span className="px-1.5 py-0.5 rounded border bg-purple-500/10 text-purple-700 dark:text-purple-300 border-purple-500/30 font-bold">
            [INFERRED] ML/Heuristic
          </span>
          <span className="px-1.5 py-0.5 rounded border bg-slate-500/10 text-slate-700 dark:text-slate-400 border-slate-500/30 font-bold">
            [NOT OBSERVABLE] Encrypted
          </span>
        </div>
      </div>

      {/* Packet Flow Strip */}
      <div className="p-5">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-2.5 mb-4">
          {packets.map((pkt, idx) => (
            <button
              key={pkt.seq}
              onClick={() => setSelectedPacket(idx)}
              className={`p-2.5 rounded-[8px] border text-left transition-all cursor-pointer ${
                selectedPacket === idx
                  ? 'border-[#4F46E5] dark:border-indigo-500 bg-indigo-50/50 dark:bg-indigo-950/30 shadow-2xs'
                  : 'border-[#E2E8F0] dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 bg-white dark:bg-[#161E2E]'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono font-bold px-1.5 py-0.2 rounded bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                  #{pkt.seq}
                </span>
                <span className={`text-[9px] font-mono font-bold px-1.5 py-0.2 rounded ${
                  pkt.status === 'danger'
                    ? 'bg-rose-100 dark:bg-rose-950/60 text-rose-800 dark:text-rose-400'
                    : pkt.status === 'warning'
                    ? 'bg-amber-100 dark:bg-amber-950/60 text-amber-800 dark:text-amber-400'
                    : 'bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-400'
                }`}>
                  {pkt.status === 'danger' ? 'VULN' : pkt.status === 'warning' ? 'WEAK' : 'SECURE'}
                </span>
              </div>

              <div className="mt-1.5 text-xs font-semibold text-[#0F172A] dark:text-white truncate">
                {pkt.exchange.split('/')[0]}
              </div>
              <div className="flex items-center justify-between mt-1 text-[10px] font-mono">
                <span className="text-[#64748B] dark:text-slate-400 truncate">{pkt.direction.split('➔')[0]}</span>
                <span className={`px-1 rounded text-[8px] font-bold border ${getObservabilityBadge(pkt.observability)}`}>
                  [{pkt.observability}]
                </span>
              </div>
            </button>
          ))}
        </div>

        {/* Selected Packet Inspection Details */}
        {packets[selectedPacket] && (
          <div className="p-4 rounded-[8px] bg-[#F6F8FB] dark:bg-[#161E2E] border border-[#E2E8F0] dark:border-slate-800 text-xs font-mono transition-colors">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pb-3 border-b border-[#E2E8F0] dark:border-slate-700/60">
              <div>
                <span className="text-[10px] text-[#64748B] dark:text-slate-400 uppercase block">Exchange Flow</span>
                <span className="font-semibold text-[#0F172A] dark:text-white">{packets[selectedPacket].direction}</span>
              </div>
              <div>
                <span className="text-[10px] text-[#64748B] dark:text-slate-400 uppercase block">Network Endpoints</span>
                <span className="text-slate-800 dark:text-slate-200">{packets[selectedPacket].src} ➔ {packets[selectedPacket].dst}</span>
              </div>
              <div>
                <span className="text-[10px] text-[#64748B] dark:text-slate-400 uppercase block">Message ID / Flags</span>
                <span className="text-slate-800 dark:text-slate-200">{packets[selectedPacket].msgId} ({packets[selectedPacket].flags})</span>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 py-3 border-b border-[#E2E8F0] dark:border-slate-700/60">
              <div>
                <span className="text-[10px] text-[#64748B] dark:text-slate-400 uppercase block">Initiator SPI</span>
                <span className="text-slate-700 dark:text-slate-300 break-all">{packets[selectedPacket].spi_i}</span>
              </div>
              <div>
                <span className="text-[10px] text-[#64748B] dark:text-slate-400 uppercase block">Responder SPI</span>
                <span className="text-slate-700 dark:text-slate-300 break-all">{packets[selectedPacket].spi_r}</span>
              </div>
            </div>

            {/* Parsed Payloads with Observability Badges */}
            <div className="py-3 border-b border-[#E2E8F0] dark:border-slate-700/60">
              <span className="text-[10px] text-[#64748B] dark:text-slate-400 uppercase block mb-1.5">
                Parsed Payloads & Cryptographic Boundary
              </span>
              <div className="flex flex-wrap gap-2">
                {packets[selectedPacket].payloads.map((payload, i) => (
                  <div key={i} className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-white dark:bg-[#111827] border border-[#E2E8F0] dark:border-slate-700 text-slate-800 dark:text-slate-200 text-[11px]">
                    <span>{typeof payload === 'string' ? payload : payload.name}</span>
                    <span className={`px-1 py-0.2 rounded text-[8px] font-bold border ${getObservabilityBadge(payload.obs || 'OBSERVED')}`}>
                      [{payload.obs || 'OBSERVED'}]
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Observability Rationale */}
            <div className="py-2.5 border-b border-[#E2E8F0] dark:border-slate-700/60 text-[11px]">
              <span className="text-[10px] text-[#64748B] dark:text-slate-400 uppercase block mb-0.5">
                Observability Taxonomy Verification:
              </span>
              <p className="text-slate-600 dark:text-slate-400 italic">
                {packets[selectedPacket].observabilityReason}
              </p>
            </div>

            <div className="pt-2.5">
              <span className="text-[10px] text-[#64748B] dark:text-slate-400 uppercase block mb-1">State Machine Protocol Telemetry</span>
              <p className="text-slate-700 dark:text-slate-300 text-[11px] leading-relaxed font-sans">
                {packets[selectedPacket].notes}
              </p>
            </div>
          </div>
        )}
      </div>

    </div>
  );
}
