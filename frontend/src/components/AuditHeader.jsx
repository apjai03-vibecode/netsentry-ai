import React from 'react';
import { Download, FileJson, Loader2, ChevronRight, ShieldAlert, ShieldCheck } from 'lucide-react';

export default function AuditHeader({ 
  assessment, 
  findingsCount = 0, 
  onDownloadPdf, 
  onDownloadJson, 
  downloadingPdf = false 
}) {
  const captureId = assessment?.upload_id ? assessment.upload_id.slice(0, 8) : '88e5cdb6';
  const hasViolations = findingsCount > 0;

  return (
    <div className="bg-white rounded-[10px] border border-[#E2E8F0] shadow-2xs overflow-hidden">
      
      {/* Top Header Row */}
      <div className="px-5 py-4 border-b border-[#E2E8F0] flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          {/* Breadcrumb Hierarchy */}
          <div className="flex items-center gap-1 text-[11px] font-mono text-[#64748B] mb-1">
            <span>Audits</span>
            <ChevronRight className="w-3 h-3 text-slate-300" />
            <span className="text-[#0F172A] font-medium">IPsec Cryptographic Compliance</span>
          </div>

          <h1 className="text-lg font-bold text-[#0F172A] tracking-tight">
            IKEv1 / IKEv2 Security Assessment
          </h1>
        </div>

        {/* Status Pill & Action Buttons */}
        <div className="flex items-center gap-2.5 flex-wrap">
          {/* Status Indicator */}
          <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono font-bold border border-rose-200 bg-rose-50 text-[#DC2626]">
            <span className="w-2 h-2 rounded-full bg-[#DC2626] animate-pulse" />
            <span>{findingsCount} Violations</span>
          </div>

          {/* Action: JSON Evidence */}
          <button
            onClick={onDownloadJson}
            title="Export raw machine-readable JSON findings for SIEM / SOC ingestion"
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-[7px] text-xs font-mono font-semibold bg-white text-[#0F172A] border border-[#E2E8F0] hover:bg-slate-50 transition-colors shadow-2xs cursor-pointer"
          >
            <FileJson className="w-3.5 h-3.5 text-[#64748B]" />
            <span>JSON Evidence</span>
          </button>

          {/* Action: Export Executive PDF */}
          <button
            onClick={onDownloadPdf}
            disabled={downloadingPdf}
            title="Generate publication-grade ReportLab PDF audit document"
            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-[7px] text-xs font-mono font-semibold bg-[#0F172A] hover:bg-slate-800 text-white transition-colors shadow-2xs cursor-pointer disabled:opacity-50"
          >
            {downloadingPdf ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin text-slate-300" />
            ) : (
              <Download className="w-3.5 h-3.5 text-slate-300" />
            )}
            <span>Export Executive PDF</span>
          </button>
        </div>
      </div>

      {/* Structured Technical Metadata Row */}
      <div className="px-5 py-3 bg-[#F6F8FB]/80 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 text-xs font-mono border-t border-[#E2E8F0]/40">
        <div>
          <span className="text-[10px] uppercase text-[#64748B] block font-semibold">Capture ID</span>
          <span className="text-[#0F172A] font-medium font-mono text-[11px] truncate block">
            {captureId}
          </span>
        </div>

        <div>
          <span className="text-[10px] uppercase text-[#64748B] block font-semibold">Source</span>
          <span className="text-[#0F172A] font-medium text-[11px] truncate block">
            192.168.1.100:500
          </span>
        </div>

        <div>
          <span className="text-[10px] uppercase text-[#64748B] block font-semibold">Destination</span>
          <span className="text-[#0F172A] font-medium text-[11px] truncate block">
            198.51.100.1:500
          </span>
        </div>

        <div>
          <span className="text-[10px] uppercase text-[#64748B] block font-semibold">Protocol</span>
          <span className="text-[#0F172A] font-medium text-[11px] block">
            IKEv1 / IKEv2
          </span>
        </div>

        <div>
          <span className="text-[10px] uppercase text-[#64748B] block font-semibold">Engine</span>
          <span className="text-[#4F46E5] font-semibold text-[11px] block">
            RFC 8247
          </span>
        </div>

        <div>
          <span className="text-[10px] uppercase text-[#64748B] block font-semibold">Assessment</span>
          <span className="text-[#0F172A] font-medium text-[11px] truncate block">
            Cryptographic Compliance
          </span>
        </div>
      </div>

    </div>
  );
}
