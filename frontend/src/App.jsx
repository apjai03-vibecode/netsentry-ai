import React, { useState, useEffect } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import Sidebar from './components/Sidebar';
import AuditHeader from './components/AuditHeader';
import SecurityPosture from './components/SecurityPosture';
import SecurityFindings from './components/SecurityFindings';
import FindingDrawer from './components/FindingDrawer';
import SessionInspector from './components/SessionInspector';
import RemediationDiff from './components/RemediationDiff';
import ModelValidation from './components/ModelValidation';
import ModelExplanation from './components/ModelExplanation';
import EngineTelemetry from './components/EngineTelemetry';
import UploadZone from './components/UploadZone';
import MLMetricsPanel from './components/MLMetricsPanel';
import RulesCatalog from './components/RulesCatalog';
import AuthModal from './components/AuthModal';
import api from './api';
import { 
  Download, 
  FileJson, 
  Loader2, 
  ShieldAlert, 
  ShieldCheck, 
  FileText, 
  CheckCircle2, 
  AlertTriangle,
  UploadCloud,
  ChevronRight,
  ExternalLink
} from 'lucide-react';

function DashboardContent() {
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState('audit');
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [showIngestBar, setShowIngestBar] = useState(false);

  const [currentJob, setCurrentJob] = useState(null);
  const [assessment, setAssessment] = useState(null);
  const [findings, setFindings] = useState([]);
  const [sessions, setSessions] = useState([]);
  const [loadingAssessment, setLoadingAssessment] = useState(false);
  const [downloadingPdf, setDownloadingPdf] = useState(false);

  // Finding drawer state
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);

  const handleSelectFinding = (finding) => {
    setSelectedFinding(finding);
    setIsDrawerOpen(true);
  };

  // Load audit data once an upload job completes
  const handleJobCompleted = async (jobId) => {
    setLoadingAssessment(true);
    try {
      const assessRes = await api.get(`/assessments/${jobId}`);
      setAssessment(assessRes.data);

      const findingsRes = await api.get(`/ingest/jobs/${jobId}/findings`);
      setFindings(findingsRes.data || []);

      const sessionsRes = await api.get(`/ingest/jobs/${jobId}/sessions`);
      setSessions(sessionsRes.data || []);

      // Switch to audit tab to show fresh results
      setActiveTab('audit');
      setShowIngestBar(false);
    } catch (err) {
      console.error('Failed to load assessment data', err);
    } finally {
      setLoadingAssessment(false);
    }
  };

  const handleDownloadPdf = async () => {
    if (!assessment || !assessment.upload_id) return;
    setDownloadingPdf(true);
    try {
      const response = await api.get(`/assessments/${assessment.upload_id}/pdf`, {
        responseType: 'blob',
      });
      const blob = new Blob([response.data], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `NetSentry-Audit-${assessment.upload_id.slice(0, 8)}.pdf`;
      link.click();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error('PDF download failed', err);
    } finally {
      setDownloadingPdf(false);
    }
  };

  const handleDownloadJson = () => {
    if (!assessment) return;
    const exportBundle = {
      assessment_id: assessment.upload_id,
      timestamp: new Date().toISOString(),
      overall_risk_score: assessment.overall_score,
      risk_level: assessment.risk_level,
      executive_summary: assessment.executive_summary,
      ml_anomaly_score: assessment.ml_anomaly_score,
      findings_count: findings.length,
      findings: findings,
      sessions: sessions,
      remediation: {
        swanctl: assessment.config_diff_after,
      },
    };
    const blob = new Blob([JSON.stringify(exportBundle, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `NetSentry-Evidence-${assessment.upload_id ? assessment.upload_id.slice(0, 8) : 'audit'}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  // Preload baseline assessment for SIH demo
  useEffect(() => {
    if (!assessment) {
      setAssessment({
        upload_id: 'demo-sample-audit-sih26160',
        overall_score: 85.0,
        risk_level: 'CRITICAL',
        executive_summary:
          'CRITICAL RISK (Score 85.0/100): The session exhibits severe cryptographic weaknesses (1 critical, 2 high findings). Immediate remediation is required to prevent potential session decryption, credential compromise, or MITM interception.',
        ml_anomaly_score: 0.82,
        config_diff_before: `# --- BEFORE (INSECURE DETECTED CONFIGURATION) ---
# File: /etc/swanctl/conf.d/vpn-tunnel.conf
connections {
    netsentry-vpn {
        version = 1
        proposals = 3des-md5-modp1024
        aggressive = yes
        local_addrs = 192.168.1.100
        remote_addrs = 198.51.100.1

        local {
            auth = psk
            id = vpn-client@domain.internal
        }
        remote {
            auth = psk
        }

        children {
            net-traffic {
                esp_proposals = 3des-md5
                mode = tunnel
                local_ts = 10.0.0.0/24
                remote_ts = 10.1.0.0/24
            }
        }
    }
}

! --- Cisco IOS Configuration ---
! Legacy IKEv1 with weak DH Group and deprecated 3DES/MD5
crypto isakmp policy 10
 encr 3des
 hash md5
 authentication pre-share
 group 2
 lifetime 86400
!
crypto ipsec transform-set LEGACY_TRANSFORM esp-3des esp-md5-hmac
 mode tunnel`,
        config_diff_after: `# +++ AFTER (HARDENED NETSENTRY REMEDIATION) +++
# File: /etc/swanctl/conf.d/vpn-tunnel.conf
connections {
    netsentry-vpn {
        version = 2
        # RFC 8247 Compliant: AEAD AES-GCM-256 with PRF-SHA256 and DH Group 14/19
        proposals = aes256gcm16-prfsha256-modp2048-ecp256, aes128gcm16-prfsha256-ecp256
        aggressive = no
        local_addrs = 192.168.1.100
        remote_addrs = 198.51.100.1

        local {
            auth = psk
            id = vpn-client@domain.internal
        }
        remote {
            auth = psk
        }

        children {
            net-traffic {
                # AEAD AES-GCM-256 with mandatory Perfect Forward Secrecy (MODP-2048 / ECP-256)
                esp_proposals = aes256gcm16-modp2048, aes256gcm16-ecp256
                mode = tunnel
                dpd_action = restart
                local_ts = 10.0.0.0/24
                remote_ts = 10.1.0.0/24
            }
        }
    }
}

! +++ Cisco IOS Remediated +++
! Modern RFC 8247 / RFC 8221 hardened IKEv2 configuration
crypto ikev2 proposal NETSENTRY_PROPOSAL
 encryption aes-gcm-256
 prf sha256
 group 19 14
!
crypto ikev2 policy NETSENTRY_POLICY
 proposal NETSENTRY_PROPOSAL
!
crypto ipsec transform-set SECURE_TRANSFORM esp-gcm 256
 mode tunnel
!
crypto ipsec profile NETSENTRY_PROFILE
 set transform-set SECURE_TRANSFORM
 set pfs group14
 set ikev2-policy NETSENTRY_POLICY`,
      });

      setFindings([
        {
          id: 1,
          rule_id: 'IKE-CRYPTO-WEAK-DH-2',
          category: 'Cryptography',
          severity: 'HIGH',
          title: 'Weak Diffie-Hellman Group 2 (1024-bit MODP) Negotiated',
          description:
            'Diffie-Hellman Group 2 uses a 1024-bit prime modulus which is susceptible to precomputation attacks (Logjam) and deprecated by RFC 8247 §2.4.',
          rfc_reference: 'RFC 8247 Section 2.4',
          remediation_hint: 'Upgrade proposal to MODP 2048 (Group 14) or Curve25519 (Group 31).',
          evidence_json: JSON.stringify({ dh_group_num: 2, dh_group_name: 'Group 2 (1024-bit MODP)' }, null, 2),
        },
        {
          id: 2,
          rule_id: 'IKE-CRYPTO-DEPRECATED-CIPHER-3DES',
          category: 'Cryptography',
          severity: 'HIGH',
          title: 'Deprecated 3DES-CBC Encryption Cipher',
          description:
            'Triple-DES uses a 64-bit block size vulnerable to Sweet32 birthday collision attacks after transferring high-volume traffic. Prohibited by RFC 8221 §5.',
          rfc_reference: 'RFC 8221 Section 5',
          remediation_hint: 'Enforce AEAD AES-GCM-256 encryption proposals.',
          evidence_json: JSON.stringify({ cipher: '3DES-CBC', block_size_bits: 64 }, null, 2),
        },
        {
          id: 3,
          rule_id: 'IKE-FLOW-AGGRESSIVE-MODE-PSK',
          category: 'Protocol Flow',
          severity: 'CRITICAL',
          title: 'IKEv1 Aggressive Mode Pre-Shared Key Hash Exposed in Cleartext',
          description:
            'IKEv1 Aggressive Mode transmits initiator ID and hash payloads in the first packet prior to DH key exchange, allowing offline cracking.',
          rfc_reference: 'RFC 2409 Section 5.4',
          remediation_hint: 'Migrate to IKEv2 Main Mode with mutual certificates or asymmetric authentication.',
          evidence_json: JSON.stringify({ exchange_type: 'Aggressive Mode', ike_version: 1 }, null, 2),
        },
      ]);
    }
  }, [assessment]);

  return (
    <div className="min-h-screen bg-[#F6F8FB] text-[#0F172A] flex font-sans antialiased">
      
      {/* Left Navigation Sidebar */}
      <Sidebar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onOpenAuth={() => setAuthModalOpen(true)}
        findingsCount={findings.length}
      />

      {/* Main Operational Stage */}
      <div className="flex-1 flex flex-col min-w-0 h-screen overflow-y-auto">
        
        {/* Top Control Bar */}
        <header className="h-14 bg-white border-b border-[#E2E8F0] px-6 flex items-center justify-between shrink-0 sticky top-0 z-20">
          <div className="flex items-center gap-2 text-xs font-mono text-[#64748B]">
            <span className="font-semibold text-[#0F172A]">NetSentry Security Center</span>
            <span>/</span>
            <span className="capitalize">{activeTab}</span>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => setShowIngestBar(!showIngestBar)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-[7px] text-xs font-mono font-medium text-[#0F172A] bg-slate-100 hover:bg-slate-200 transition-colors cursor-pointer"
            >
              <UploadCloud className="w-3.5 h-3.5 text-[#4F46E5]" />
              <span>{showIngestBar ? 'Hide Ingest Bar' : 'Quick Ingest'}</span>
            </button>

            <div className="inline-flex items-center gap-1 px-2 py-0.5 rounded-[5px] bg-emerald-50 text-[#059669] text-[10px] font-mono font-semibold border border-emerald-200">
              <span className="w-1.5 h-1.5 rounded-full bg-[#059669] animate-pulse" />
              <span>SOC Agent Ready</span>
            </div>
          </div>
        </header>

        {/* Collapsible Quick Ingest Bar */}
        {showIngestBar && (
          <div className="p-6 bg-slate-50 border-b border-[#E2E8F0]">
            <div className="max-w-5xl mx-auto">
              <UploadZone
                onJobStarted={(job) => setCurrentJob(job)}
                onJobCompleted={handleJobCompleted}
                onOpenAuth={() => setAuthModalOpen(true)}
              />
            </div>
          </div>
        )}

        {/* Content Container */}
        <main className="flex-1 p-6 max-w-7xl w-full mx-auto space-y-6 pb-12">
          
          {/* 1. Main Audit Dashboard */}
          {(activeTab === 'audit' || activeTab === 'dashboard') && (
            <>
              {/* Audit Context & Metadata Header */}
              <AuditHeader
                assessment={assessment}
                findingsCount={findings.length}
                onDownloadPdf={handleDownloadPdf}
                onDownloadJson={handleDownloadJson}
                downloadingPdf={downloadingPdf}
              />

              {loadingAssessment ? (
                <div className="bg-white rounded-[10px] border border-[#E2E8F0] p-12 text-center flex flex-col items-center justify-center shadow-2xs">
                  <Loader2 className="w-8 h-8 text-[#4F46E5] animate-spin mb-3" />
                  <span className="text-xs font-mono font-semibold text-[#0F172A]">
                    Executing Triple-Engine Audit Pipeline...
                  </span>
                  <span className="text-[11px] font-mono text-[#64748B] mt-1">
                    RFC 8247 Rule Matcher • Stateful FSM State Machine • XGBoost & Tree SHAP Inference
                  </span>
                </div>
              ) : (
                assessment && (
                  <div className="space-y-6">
                    {/* Security Posture */}
                    <SecurityPosture
                      assessment={assessment}
                      findings={findings}
                    />

                    {/* Security Findings */}
                    <SecurityFindings
                      findings={findings}
                      onSelectFinding={handleSelectFinding}
                    />

                    {/* Handshake Sequence & State Inspector */}
                    <SessionInspector
                      assessment={assessment}
                      findings={findings}
                    />

                    {/* Remediation Diffs */}
                    <RemediationDiff
                      assessment={assessment}
                    />

                    {/* Model Validation */}
                    <ModelValidation />

                    {/* Model Explanation */}
                    <ModelExplanation
                      assessment={assessment}
                    />

                    {/* Engine Telemetry */}
                    <EngineTelemetry
                      assessment={assessment}
                    />
                  </div>
                )
              )}
            </>
          )}

          {/* 2. Dedicated Capture Ingest Tab */}
          {activeTab === 'captures' && (
            <div className="space-y-6">
              <div className="bg-white rounded-[10px] border border-[#E2E8F0] p-5 shadow-2xs">
                <h2 className="text-sm font-bold font-mono text-[#0F172A] uppercase tracking-wider mb-1">
                  Network Capture Ingestion & Dissection Engine
                </h2>
                <p className="text-xs text-[#64748B] font-mono">
                  Upload raw .pcap or .pcapng captures for automated Scapy 28-byte unpadded header parsing and cryptographic verification.
                </p>
              </div>

              <UploadZone
                onJobStarted={(job) => setCurrentJob(job)}
                onJobCompleted={handleJobCompleted}
                onOpenAuth={() => setAuthModalOpen(true)}
              />

              <SessionInspector
                assessment={assessment}
                findings={findings}
              />
            </div>
          )}

          {/* 3. Dedicated Findings Catalog Tab */}
          {activeTab === 'findings' && (
            <div className="space-y-6">
              <SecurityFindings
                findings={findings}
                onSelectFinding={handleSelectFinding}
              />
            </div>
          )}

          {/* 4. Dedicated ML Intelligence Tab */}
          {activeTab === 'ml' && (
            <div className="space-y-6">
              <ModelValidation />
              <ModelExplanation assessment={assessment} />
              <MLMetricsPanel />
            </div>
          )}

          {/* 5. Dedicated RFC Library Tab */}
          {activeTab === 'rules' && (
            <div className="space-y-6">
              <RulesCatalog />
            </div>
          )}

          {/* 6. Dedicated Remediation Diffs Tab */}
          {activeTab === 'remediation' && (
            <div className="space-y-6">
              <RemediationDiff assessment={assessment} />
            </div>
          )}

          {/* 7. Dedicated Audit Reports Tab */}
          {activeTab === 'reports' && (
            <div className="space-y-6">
              <div className="bg-white rounded-[10px] border border-[#E2E8F0] p-6 shadow-2xs space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#E2E8F0] pb-4">
                  <div>
                    <h2 className="text-sm font-bold font-mono text-[#0F172A] uppercase tracking-wider">
                      Audit Certification & Executive Export
                    </h2>
                    <p className="text-xs text-[#64748B] font-mono mt-0.5">
                      Formal assessment report compliant with IETF RFC 8247 & RFC 8221 specifications
                    </p>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={handleDownloadJson}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-[7px] text-xs font-mono font-semibold bg-white text-[#0F172A] border border-[#E2E8F0] hover:bg-slate-50 transition-colors shadow-2xs cursor-pointer"
                    >
                      <FileJson className="w-3.5 h-3.5 text-[#64748B]" />
                      <span>Download JSON Evidence</span>
                    </button>

                    <button
                      onClick={handleDownloadPdf}
                      disabled={downloadingPdf}
                      className="inline-flex items-center gap-1.5 px-4 py-1.5 rounded-[7px] text-xs font-mono font-semibold bg-[#0F172A] hover:bg-slate-800 text-white transition-colors shadow-2xs cursor-pointer disabled:opacity-50"
                    >
                      {downloadingPdf ? (
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      ) : (
                        <Download className="w-3.5 h-3.5" />
                      )}
                      <span>Export Executive PDF</span>
                    </button>
                  </div>
                </div>

                {/* Executive Summary Block */}
                <div className="p-4 rounded-[8px] bg-[#F6F8FB] border border-[#E2E8F0] space-y-2">
                  <span className="text-[10px] uppercase font-mono font-bold text-[#64748B] block">
                    Executive Summary Statement
                  </span>
                  <p className="text-xs text-[#0F172A] font-sans leading-relaxed">
                    {assessment?.executive_summary}
                  </p>
                </div>

                {/* Sign-Off Checklist */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono pt-2">
                  <div className="p-3 bg-white border border-[#E2E8F0] rounded-[8px]">
                    <span className="text-[10px] text-[#64748B] block">Overall Risk Rating</span>
                    <span className="text-sm font-extrabold text-[#DC2626] mt-0.5 block">
                      {assessment?.risk_level} ({assessment?.overall_score}/100)
                    </span>
                  </div>

                  <div className="p-3 bg-white border border-[#E2E8F0] rounded-[8px]">
                    <span className="text-[10px] text-[#64748B] block">Violations Count</span>
                    <span className="text-sm font-extrabold text-[#D97706] mt-0.5 block">
                      {findings.length} Flagged Parameters
                    </span>
                  </div>

                  <div className="p-3 bg-white border border-[#E2E8F0] rounded-[8px]">
                    <span className="text-[10px] text-[#64748B] block">Engine Conformance</span>
                    <span className="text-sm font-extrabold text-[#059669] mt-0.5 block">
                      RFC 8247 Certified
                    </span>
                  </div>
                </div>
              </div>
            </div>
          )}

        </main>
      </div>

      {/* Slide-Over Forensic Finding Drawer */}
      <FindingDrawer
        finding={selectedFinding}
        isOpen={isDrawerOpen}
        onClose={() => setIsDrawerOpen(false)}
      />

      {/* Authentication Modal */}
      <AuthModal
        isOpen={authModalOpen}
        onClose={() => setAuthModalOpen(false)}
      />

    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <DashboardContent />
    </AuthProvider>
  );
}
