import React from 'react';
import { BookOpen, ShieldCheck, ShieldAlert, CheckCircle, ExternalLink } from 'lucide-react';

export default function RulesCatalog() {
  const rules = [
    {
      id: 'IKE-CRYPTO-WEAK-DH-1',
      name: 'Diffie-Hellman Group 1 (768-bit MODP) Deprecated',
      severity: 'CRITICAL',
      rfc: 'RFC 8247 Section 2.4',
      description: 'DH Group 1 has an effective security level well below 80 bits and can be broken within hours using commodity GPU clusters.',
      remediation: 'Upgrade to DH Group 14 (2048-bit MODP) or Group 19 (256-bit Random ECP).',
    },
    {
      id: 'IKE-CRYPTO-WEAK-DH-2',
      name: 'Diffie-Hellman Group 2 (1024-bit MODP) Deprecated',
      severity: 'HIGH',
      rfc: 'RFC 8247 Section 2.4',
      description: 'DH Group 2 was formally retired by NIST and IETF due to practical number field sieve factorization risks (Logjam attack).',
      remediation: 'Migrate to DH Group 14 (MODP 2048) or Curve25519 (RFC 8031).',
    },
    {
      id: 'IKE-CRYPTO-DEPRECATED-CIPHER-3DES',
      name: 'Triple-DES (3DES-CBC) Sweet32 Vulnerability',
      severity: 'HIGH',
      rfc: 'RFC 8221 Section 5',
      description: '3DES has a 64-bit block size susceptible to birthday collision attacks (Sweet32) after only 32GB of encrypted transfer.',
      remediation: 'Replace with AEAD ciphers like AES-256-GCM or AES-128-GCM.',
    },
    {
      id: 'IKE-CRYPTO-DEPRECATED-CIPHER-DES',
      name: 'Single DES-CBC Broken Symmetric Cipher',
      severity: 'CRITICAL',
      rfc: 'RFC 8221 Section 5',
      description: 'DES uses a 56-bit key space vulnerable to real-time brute-force cracking within minutes.',
      remediation: 'Completely eliminate DES proposals and enforce AES-GCM-256.',
    },
    {
      id: 'IKE-CRYPTO-DEPRECATED-INTEG-MD5',
      name: 'MD5 Integrity / PRF Algorithm Deprecated',
      severity: 'HIGH',
      rfc: 'RFC 8247 Section 2.2',
      description: 'MD5 is cryptographically broken with practical collision generation techniques.',
      remediation: 'Upgrade to SHA-256 PRF (AUTH_HMAC_SHA2_256_128) or use AEAD cipher suites.',
    },
    {
      id: 'IKE-FLOW-AGGRESSIVE-MODE-PSK',
      name: 'IKEv1 Aggressive Mode Pre-Shared Key Exposure',
      severity: 'CRITICAL',
      rfc: 'RFC 2409 Section 5.4',
      description: 'Aggressive mode transmits identity payloads and hashed authentication tokens before DH negotiation, enabling offline dictionary attacks.',
      remediation: 'Upgrade immediately to IKEv2 (RFC 7296) or use Main Mode with digital certificates.',
    },
    {
      id: 'IKE-CRYPTO-NO-PFS',
      name: 'Child SA Missing Perfect Forward Secrecy (PFS)',
      severity: 'MEDIUM',
      rfc: 'RFC 7296 Section 1.3',
      description: 'Without PFS, compromise of the long-term IKE SA master key allows passive retrospective decryption of all past traffic.',
      remediation: 'Enable mandatory Diffie-Hellman re-exchange for CREATE_CHILD_SA (set pfs=yes or set pfs group14).',
    },
    {
      id: 'IKE-FSM-TRUNCATED-HANDSHAKE',
      name: 'Premature Handshake Termination / Negotiation Failure',
      severity: 'HIGH',
      rfc: 'RFC 7296 / NetSentry FSM',
      description: 'Session initiated SA exchange but abruptly terminated before mutual authentication or Child SA establishment.',
      remediation: 'Inspect proposal mismatches, firewall UDP 500/4500 dropping, or certificate validation errors.',
    },
  ];

  return (
    <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs">
      <div className="pb-4 border-b border-slate-100">
        <div className="flex items-center gap-2">
          <div className="w-9 h-9 rounded-xl bg-indigo-50 text-indigo-600 flex items-center justify-center">
            <BookOpen className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-slate-900">RFC Standards & Rule Catalog</h2>
            <p className="text-xs text-slate-500">
              Cryptographic and stateful security rules codified from RFC 8247, RFC 8221, RFC 7296, and NIST SP 800-57
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5 mt-4">
        {rules.map((r) => {
          let badgeClass = 'bg-amber-50 text-amber-800 border-amber-200';
          if (r.severity === 'CRITICAL') badgeClass = 'bg-rose-50 text-rose-800 border-rose-200';
          if (r.severity === 'HIGH') badgeClass = 'bg-orange-50 text-orange-800 border-orange-200';
          if (r.severity === 'MEDIUM') badgeClass = 'bg-amber-50 text-amber-800 border-amber-200';

          const rfcNum = r.rfc.match(/RFC\s*(\d+)/i)?.[1];
          const rfcLink = rfcNum ? `https://datatracker.ietf.org/doc/html/rfc${rfcNum}` : null;

          return (
            <div key={r.id} className="p-4 rounded-lg border border-slate-200 bg-white hover:border-slate-300 transition-colors flex flex-col justify-between shadow-2xs">
              <div>
                <div className="flex items-center justify-between gap-2 mb-2">
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-0.5 text-[10px] font-mono font-bold rounded border ${badgeClass}`}>
                      {r.severity}
                    </span>
                    <span className="text-[11px] font-mono text-slate-500">
                      {r.id}
                    </span>
                  </div>

                  {rfcLink ? (
                    <a
                      href={rfcLink}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-[11px] font-mono text-indigo-600 hover:text-indigo-800 bg-indigo-50/70 hover:bg-indigo-100 px-2 py-0.5 rounded border border-indigo-200/60 transition-colors"
                      title="Read full IETF RFC specification"
                    >
                      <span>{r.rfc}</span>
                      <ExternalLink className="w-2.5 h-2.5 opacity-60" />
                    </a>
                  ) : (
                    <span className="text-[11px] font-mono text-slate-500 bg-slate-100 px-2 py-0.5 rounded">
                      {r.rfc}
                    </span>
                  )}
                </div>

                <h4 className="text-xs font-bold text-slate-900">{r.name}</h4>
                <p className="text-[11px] text-slate-600 mt-1 leading-relaxed">{r.description}</p>
              </div>

              <div className="mt-3 pt-2 border-t border-slate-100 text-[11px] font-mono text-emerald-900 bg-emerald-50/60 p-2 rounded">
                <span className="font-bold text-emerald-950 font-sans">Hardening Action:</span> {r.remediation}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

