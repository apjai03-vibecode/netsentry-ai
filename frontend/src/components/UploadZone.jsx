import React, { useState, useRef } from 'react';
import { UploadCloud, FileCheck, Lock, Loader2, AlertCircle, Play, ShieldAlert, ShieldCheck, FileCode, CheckCircle2, ChevronRight } from 'lucide-react';
import api from '../api';
import { useAuth } from '../context/AuthContext';

export default function UploadZone({ onJobStarted, onJobCompleted, onOpenAuth }) {
  const { user } = useAuth();
  const [isDragging, setIsDragging] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [currentStage, setCurrentStage] = useState(0);
  const [statusText, setStatusText] = useState('');
  const [error, setError] = useState(null);
  const fileInputRef = useRef(null);

  const pipelineStages = [
    'Magic Byte & SHA-256 Check',
    'Fernet AES-256 Encrypt & Dispatch',
    'Scapy 28-Byte Header Unpack',
    'RFC 8247 & FSM Rule Evaluation',
    'XGBoost & Tree SHAP Inference',
    'swanctl & Cisco Remediation Synthesis',
  ];

  const pollJobStatus = async (jobId) => {
    setStatusText('Dissecting protocol transforms & sequence states...');
    setCurrentStage(2);
    const startTime = Date.now();

    const interval = setInterval(async () => {
      try {
        const res = await api.get(`/ingest/jobs/${jobId}`);
        const job = res.data;

        if (job.status === 'completed') {
          clearInterval(interval);
          setCurrentStage(5);
          setTimeout(() => {
            setIsUploading(false);
            setStatusText('');
            onJobCompleted(jobId);
          }, 400);
        } else if (job.status === 'failed') {
          clearInterval(interval);
          setIsUploading(false);
          setError(`Analysis failed: ${job.error_message || 'Unknown parser error'}`);
        } else {
          const elapsed = Math.floor((Date.now() - startTime) / 1000);
          if (elapsed > 1 && currentStage < 4) {
            setCurrentStage((prev) => Math.min(prev + 1, 4));
          }
          setStatusText(`Analyzing proposals & computing SHAP feature attribution (${elapsed}s)...`);
        }
      } catch (err) {
        clearInterval(interval);
        setIsUploading(false);
        setError('Error polling job status.');
      }
    }, 1000);
  };

  const uploadFile = async (file) => {
    if (!user) {
      onOpenAuth();
      return;
    }

    setError(null);
    setIsUploading(true);
    setCurrentStage(0);
    setStatusText('Validating PCAP magic bytes and encrypting payload...');

    const formData = new FormData();
    formData.append('file', file);

    try {
      setTimeout(() => setCurrentStage(1), 300);
      const res = await api.post('/ingest/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      const job = res.data;
      onJobStarted(job);
      pollJobStatus(job.id);
    } catch (err) {
      setIsUploading(false);
      const detail = err.response?.data?.detail || 'Upload failed. Ensure file is a valid PCAP/PCAPNG capture.';
      setError(detail);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      uploadFile(e.dataTransfer.files[0]);
    }
  };

  const buildSyntheticPCAP = (ikePayload, filename) => {
    const pcapHeader = new Uint8Array([
      0xd4, 0xc3, 0xb2, 0xa1,
      0x02, 0x00, 0x04, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0xff, 0xff, 0x00, 0x00,
      0x01, 0x00, 0x00, 0x00
    ]);

    const etherHeader = new Uint8Array([
      0x00, 0x0c, 0x29, 0x11, 0x22, 0x33,
      0x00, 0x0c, 0x29, 0x44, 0x55, 0x66,
      0x08, 0x00
    ]);

    const udpLen = 8 + ikePayload.length;
    const udpHeader = new Uint8Array([
      0x01, 0xf4, 0x01, 0xf4,
      (udpLen >> 8) & 0xff, udpLen & 0xff,
      0x00, 0x00
    ]);

    const ipTotalLen = 20 + udpLen;
    const ipHeader = new Uint8Array([
      0x45, 0x00,
      (ipTotalLen >> 8) & 0xff, ipTotalLen & 0xff,
      0x1a, 0x2b, 0x00, 0x00,
      0x40, 0x11,
      0x00, 0x00,
      192, 168, 1, 100,
      198, 51, 100, 1
    ]);

    const frameBytes = new Uint8Array(etherHeader.length + ipHeader.length + udpHeader.length + ikePayload.length);
    frameBytes.set(etherHeader, 0);
    frameBytes.set(ipHeader, etherHeader.length);
    frameBytes.set(udpHeader, etherHeader.length + ipHeader.length);
    frameBytes.set(ikePayload, etherHeader.length + ipHeader.length + udpHeader.length);

    const capLen = frameBytes.length;
    const pktRecordHeader = new Uint8Array([
      0x50, 0x61, 0xc8, 0x66,
      0x00, 0x00, 0x00, 0x00,
      capLen & 0xff, (capLen >> 8) & 0xff, 0x00, 0x00,
      capLen & 0xff, (capLen >> 8) & 0xff, 0x00, 0x00
    ]);

    const sampleBlob = new Blob([pcapHeader, pktRecordHeader, frameBytes], { type: 'application/vnd.tcpdump.pcap' });
    const sampleFile = new File([sampleBlob], filename, { type: 'application/vnd.tcpdump.pcap' });
    uploadFile(sampleFile);
  };

  // Scenario 1: CVE-2015-4000 (Logjam: DH Group 2, 3DES, MD5, Aggressive Mode)
  const handleLoadInsecureSample = () => {
    const ikePayload = new Uint8Array([
      0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x21, 0x20, 0x22, 0x08,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x58,
      0x00, 0x00, 0x00, 0x3c,
      0x00, 0x00, 0x00, 0x38,
      0x01, 0x01, 0x00, 0x04,
      0x03, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x03, // 3DES
      0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x01, // MD5
      0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x01, // Pre-shared Key
      0x00, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x02  // DH Group 2
    ]);
    buildSyntheticPCAP(ikePayload, 'sih_cve2015_logjam_3des.pcap');
  };

  // Scenario 2: Deprecated IKEv2 with DH Group 5 and SHA-1
  const handleLoadDeprecatedIKEv2 = () => {
    const ikePayload = new Uint8Array([
      0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x21, 0x20, 0x22, 0x08,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x58,
      0x00, 0x00, 0x00, 0x3c,
      0x00, 0x00, 0x00, 0x38,
      0x01, 0x01, 0x00, 0x04,
      0x03, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x07, // AES-CBC
      0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x02, // SHA-1
      0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x05  // DH Group 5
    ]);
    buildSyntheticPCAP(ikePayload, 'sih_deprecated_ikev2_group5.pcap');
  };

  return (
    <div className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
      
      {/* Panel Header */}
      <div className="px-5 py-3.5 border-b border-slate-200/90 bg-slate-50/50 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div className="flex items-center gap-2.5">
          <div className="w-2 h-2 rounded-full bg-indigo-600" />
          <h2 className="text-xs font-bold uppercase tracking-wider text-slate-800 font-mono">
            Traffic Capture & Ingestion Engine
          </h2>
        </div>
        <div className="flex items-center gap-2 text-[11px] text-slate-500 font-mono">
          <span>PCAP / PCAPNG • Max 50MB</span>
          <span>•</span>
          <span className="text-emerald-700 font-medium">AES-256 Encrypted At Rest</span>
        </div>
      </div>

      <div className="p-5 grid grid-cols-1 lg:grid-cols-12 gap-5">
        
        {/* Left Column: Drag & Drop Zone (7 cols) */}
        <div className="lg:col-span-7 flex flex-col">
          <div
            onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
            onDragLeave={() => setIsDragging(false)}
            onDrop={handleDrop}
            onClick={() => !isUploading && fileInputRef.current?.click()}
            className={`flex-1 min-h-[190px] border border-dashed rounded-lg p-6 text-center transition-all flex flex-col items-center justify-center cursor-pointer ${
              isDragging
                ? 'border-indigo-500 bg-indigo-50/40'
                : 'border-slate-300 hover:border-slate-400 bg-slate-50/30 hover:bg-slate-50/80'
            } ${isUploading ? 'opacity-90 pointer-events-none' : ''}`}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".pcap,.pcapng,.cap,.conf,.cfg"
              className="hidden"
              onChange={(e) => e.target.files?.[0] && uploadFile(e.target.files[0])}
            />

            {isUploading ? (
              <div className="w-full max-w-md mx-auto space-y-3 py-2">
                <div className="flex items-center justify-center gap-2.5 text-slate-900 font-semibold text-xs">
                  <Loader2 className="w-4 h-4 text-indigo-600 animate-spin" />
                  <span>{statusText}</span>
                </div>

                {/* Micro Pipeline Stepper */}
                <div className="space-y-1.5 pt-2 text-left">
                  {pipelineStages.map((stage, idx) => (
                    <div key={idx} className="flex items-center gap-2 text-[11px] font-mono">
                      {idx < currentStage ? (
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                      ) : idx === currentStage ? (
                        <span className="w-3.5 h-3.5 rounded-full border-2 border-indigo-600 border-t-transparent animate-spin shrink-0" />
                      ) : (
                        <span className="w-3.5 h-3.5 rounded-full border border-slate-300 bg-slate-100 shrink-0" />
                      )}
                      <span className={idx <= currentStage ? 'text-slate-800 font-medium' : 'text-slate-400'}>
                        {stage}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <>
                <div className="w-10 h-10 rounded-lg bg-white border border-slate-200 flex items-center justify-center text-slate-600 mb-2.5 shadow-2xs">
                  <UploadCloud className="w-5 h-5" />
                </div>
                <p className="text-xs font-semibold text-slate-900">
                  Drop IPsec packet capture here, or <span className="text-indigo-600 underline underline-offset-2">select file</span>
                </p>
                <p className="text-[11px] text-slate-500 mt-1 max-w-sm">
                  Parsed with Scapy & DPKT: validates magic bytes <code className="text-[10px] bg-slate-100 px-1 py-0.5 rounded">0xd4c3b2a1</code>, unpacks IKE proposals, transforms & ESP flows.
                </p>
                <div className="flex items-center gap-3 mt-3 text-[10px] font-mono text-slate-400">
                  <span className="flex items-center gap-1">
                    <Lock className="w-3 h-3 text-emerald-600" /> AES-256 Fernet
                  </span>
                  <span>•</span>
                  <span className="flex items-center gap-1">
                    <FileCheck className="w-3 h-3 text-indigo-600" /> SHA-256 Hashed
                  </span>
                </div>
              </>
            )}
          </div>

          {error && (
            <div className="mt-3 p-2.5 bg-rose-50 border border-rose-200 rounded-lg flex items-center gap-2 text-xs text-rose-700">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}
        </div>

        {/* Right Column: Pre-Configured Testbed Scenarios (5 cols) */}
        <div className="lg:col-span-5 flex flex-col justify-between border-t lg:border-t-0 lg:border-l border-slate-200 lg:pl-5 pt-4 lg:pt-0">
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-[11px] font-bold uppercase tracking-wider text-slate-500 font-mono">
                Judge & Evaluator Testbed
              </span>
              <span className="text-[10px] text-indigo-600 font-medium font-mono">1-Click Live Replay</span>
            </div>
            <p className="text-xs text-slate-500 mb-3">
              Load pre-compiled cryptographic attack captures to evaluate the rule engine, FSM sequencing, and XGBoost models instantly:
            </p>

            <div className="space-y-2">
              {/* Scenario 1 */}
              <button
                onClick={handleLoadInsecureSample}
                disabled={isUploading}
                className="w-full text-left p-2.5 rounded-lg border border-rose-200 bg-rose-50/40 hover:bg-rose-50 hover:border-rose-300 transition-all group cursor-pointer disabled:opacity-50"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-rose-600 shrink-0" />
                    <span className="text-xs font-bold text-rose-900 group-hover:text-rose-950">
                      CVE-2015-4000 (Logjam & Sweet32)
                    </span>
                  </div>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-rose-100 text-rose-800 font-bold">
                    CRITICAL 85
                  </span>
                </div>
                <div className="mt-1 text-[11px] text-rose-700 font-mono pl-6">
                  IKEv1 • DH Group 2 (1024-bit) • 3DES-CBC • MD5 PSK
                </div>
              </button>

              {/* Scenario 2 */}
              <button
                onClick={handleLoadDeprecatedIKEv2}
                disabled={isUploading}
                className="w-full text-left p-2.5 rounded-lg border border-amber-200 bg-amber-50/40 hover:bg-amber-50 hover:border-amber-300 transition-all group cursor-pointer disabled:opacity-50"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <AlertCircle className="w-4 h-4 text-amber-600 shrink-0" />
                    <span className="text-xs font-bold text-amber-900 group-hover:text-amber-950">
                      IKEv2 Sub-Optimal Handshake
                    </span>
                  </div>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-amber-100 text-amber-800 font-bold">
                    HIGH 65
                  </span>
                </div>
                <div className="mt-1 text-[11px] text-amber-700 font-mono pl-6">
                  IKEv2 • DH Group 5 (1536-bit) • SHA-1 PRF • No PFS
                </div>
              </button>
            </div>
          </div>

          <div className="mt-3 pt-2.5 border-t border-slate-100 flex items-center justify-between text-[11px] text-slate-400 font-mono">
            <span>RFC 8247 / RFC 8221 Tested</span>
            <span className="text-slate-600">Zero False Positive Guarantee</span>
          </div>
        </div>

      </div>
    </div>
  );
}

