import React, { useState, useRef } from 'react';
import { UploadCloud, FileCheck, Lock, Sparkles, Loader2, AlertCircle } from 'lucide-react';
import api from '../api';
import { useAuth } from '../context/AuthContext';

export default function UploadZone({ onJobStarted, onJobCompleted, onOpenAuth }) {
  const { user } = useAuth();
  const [isDragging, setIsDragging] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [statusText, setStatusText] = useState('');
  const [error, setError] = useState(null);
  const fileInputRef = useRef(null);

  const pollJobStatus = async (jobId) => {
    setStatusText('Analyzing protocol handshakes with Scapy & XGBoost...');
    const startTime = Date.now();

    const interval = setInterval(async () => {
      try {
        const res = await api.get(`/ingest/jobs/${jobId}`);
        const job = res.data;

        if (job.status === 'completed') {
          clearInterval(interval);
          setIsUploading(false);
          setStatusText('');
          onJobCompleted(jobId);
        } else if (job.status === 'failed') {
          clearInterval(interval);
          setIsUploading(false);
          setError(`Analysis failed: ${job.error_message || 'Unknown parser error'}`);
        } else {
          const elapsedSec = Math.floor((Date.now() - startTime) / 1000);
          setStatusText(`Parsing packets and running RFC & ML engines (${elapsedSec}s)...`);
        }
      } catch (err) {
        clearInterval(interval);
        setIsUploading(false);
        setError('Error polling job status.');
      }
    }, 1200);
  };

  const uploadFile = async (file) => {
    if (!user) {
      onOpenAuth();
      return;
    }

    setError(null);
    setIsUploading(true);
    setStatusText('Encrypting capture and dispatching to Celery worker...');

    const formData = new FormData();
    formData.append('file', file);

    try {
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

  const handleLoadSamplePCAP = () => {
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

    const ikePayload = new Uint8Array([
      0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x21, 0x20, 0x22, 0x08,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x58,
      0x00, 0x00, 0x00, 0x3c,
      0x00, 0x00, 0x00, 0x38,
      0x01, 0x01, 0x00, 0x04,
      0x03, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x03,
      0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x01,
      0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x02
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
    const sampleFile = new File([sampleBlob], 'sih26160_insecure_vpn_sample.pcap', { type: 'application/vnd.tcpdump.pcap' });
    uploadFile(sampleFile);
  };

  return (
    <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs">
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 pb-4 border-b border-slate-100">
        <div>
          <h2 className="text-lg font-bold text-slate-900">Upload Traffic Capture</h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Accepts raw IPsec captures (.pcap, .pcapng) or strongSwan / Cisco configurations up to 50MB.
          </p>
        </div>

        <button
          onClick={handleLoadSamplePCAP}
          disabled={isUploading}
          className="inline-flex items-center gap-2 px-3.5 py-2 bg-gradient-to-r from-amber-500 to-orange-500 hover:from-amber-600 hover:to-orange-600 text-white text-xs font-semibold rounded-xl shadow-xs shadow-amber-200 transition-all cursor-pointer disabled:opacity-50"
        >
          <Sparkles className="w-4 h-4" />
          <span>⚡ Test with Insecure Sample PCAP</span>
        </button>
      </div>

      <div
        onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={handleDrop}
        onClick={() => !isUploading && fileInputRef.current?.click()}
        className={`mt-4 border-2 border-dashed rounded-xl p-8 text-center transition-all cursor-pointer ${
          isDragging
            ? 'border-indigo-500 bg-indigo-50/50'
            : 'border-slate-200 hover:border-indigo-300 hover:bg-slate-50/50'
        } ${isUploading ? 'opacity-70 cursor-not-allowed' : ''}`}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".pcap,.pcapng,.cap,.conf,.cfg"
          className="hidden"
          onChange={(e) => e.target.files?.[0] && uploadFile(e.target.files[0])}
        />

        {isUploading ? (
          <div className="flex flex-col items-center justify-center py-4">
            <Loader2 className="w-10 h-10 text-indigo-600 animate-spin mb-3" />
            <span className="text-sm font-semibold text-slate-800">{statusText}</span>
            <span className="text-xs text-slate-400 mt-1">Scapy Dissection • FSM Tracker • XGBoost • SHAP</span>
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center">
            <div className="w-12 h-12 rounded-2xl bg-indigo-50 text-indigo-600 flex items-center justify-center mb-3">
              <UploadCloud className="w-6 h-6" />
            </div>
            <p className="text-sm font-semibold text-slate-800">
              Drag & drop packet capture file, or <span className="text-indigo-600 hover:underline">browse</span>
            </p>
            <p className="text-xs text-slate-400 mt-1">
              Supports IKEv1, IKEv2, ESP Protocol 50, and Cisco / strongSwan config files
            </p>

            <div className="flex items-center gap-4 mt-4 text-[11px] text-slate-500">
              <span className="flex items-center gap-1">
                <Lock className="w-3 h-3 text-emerald-600" />
                Fernet AES-256 at-rest encryption
              </span>
              <span className="flex items-center gap-1">
                <FileCheck className="w-3 h-3 text-indigo-600" />
                SHA-256 integrity checked
              </span>
            </div>
          </div>
        )}
      </div>

      {error && (
        <div className="mt-3 p-3 bg-rose-50 border border-rose-200 rounded-xl flex items-center gap-2 text-xs text-rose-700">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}
    </div>
  );
}
