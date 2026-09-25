import React, { useState, useEffect } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { ThemeProvider, useTheme } from './context/ThemeContext';
import ThemeToggle from './components/ThemeToggle';
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
import ThreatMatrix from './components/ThreatMatrix';
import TrafficIntelligence from './components/TrafficIntelligence';
import MetadataExposure from './components/MetadataExposure';
import TestbedLab from './components/TestbedLab';
import api from './api';
import { 
  Download, 
  FileJson, 
  Loader2, 
  UploadCloud, 
  Menu, 
  User, 
  Palette,
  Sun,
  Moon,
  Monitor
} from 'lucide-react';

function DashboardContent() {
  const { user } = useAuth();
  const { theme, setTheme } = useTheme();
  const [activeTab, setActiveTab] = useState('audit');
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [showIngestBar, setShowIngestBar] = useState(false);
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);

  const [currentJob, setCurrentJob] = useState(null);
  const [assessment, setAssessment] = useState(null);
  const [findings, setFindings] = useState([]);
  const [sessions, setSessions] = useState([]);
  const [threatMatrixData, setThreatMatrixData] = useState(null);
  const [metadataExposureData, setMetadataExposureData] = useState(null);
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

      try {
        const tmRes = await api.get(`/assessments/${jobId}/threat-matrix`);
        setThreatMatrixData(tmRes.data);
      } catch (e) {
        console.warn('Threat matrix fetch failed:', e);
      }

      try {
        const meRes = await api.get(`/assessments/${jobId}/metadata-exposure`);
        setMetadataExposureData(meRes.data);
      } catch (e) {
        console.warn('Metadata exposure fetch failed:', e);
      }

      // Switch to audit tab to show fresh results
      setActiveTab('audit');
      setShowIngestBar(false);
    } catch (err) {
      console.error('Failed to load assessment data', err);
    } finally {
      setLoadingAssessment(false);
    }
  };

  const handleDownloadPdf = async (type = 'executive') => {
    if (!assessment || !assessment.upload_id) return;
    setDownloadingPdf(true);
    try {
      const endpoint = type === 'technical'
        ? `/assessments/${assessment.upload_id}/technical-pdf`
        : `/assessments/${assessment.upload_id}/executive-pdf`;
      const response = await api.get(endpoint, {
        responseType: 'blob',
      });
      const blob = new Blob([response.data], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `NetSentry-${type === 'technical' ? 'Technical' : 'Executive'}-Audit-${assessment.upload_id.slice(0, 8)}.pdf`;
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
        upload_id: '88e5cdb6-sample-audit',
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
          severity: 'CRITICAL',
          title: 'Weak Diffie-Hellman Group 2 (1024-bit MODP) Negotiated',
          description:
            'Group 1/2/5 detected. Diffie-Hellman Group 2 uses a 1024-bit prime modulus susceptible to discrete log precomputation attacks (Logjam). Prohibited by RFC 8247 §2.4.',
          rfc_reference: 'RFC 8247 Section 2.4',
          remediation_hint: 'Upgrade proposal to MODP 2048 (Group 14) or ECP 256 (Group 19).',
          evidence_json: JSON.stringify({ dh_group_num: 2, dh_group_name: 'Group 2 (1024-bit MODP)', cipher: '3DES-CBC', ike_version: 1 }, null, 2),
        },
        {
          id: 2,
          rule_id: 'IKE-CRYPTO-DEPRECATED-CIPHER-3DES',
          category: 'Cryptography',
          severity: 'HIGH',
          title: 'Deprecated 3DES / DES Cipher Detected',
          description:
            '3DES / DES detected. Triple-DES uses a 64-bit block size vulnerable to Sweet32 birthday collision attacks after transferring high-volume traffic. Prohibited by RFC 8221 §5.',
          rfc_reference: 'RFC 8221 Section 5',
          remediation_hint: 'Enforce AEAD AES-GCM-256 encryption proposals.',
          evidence_json: JSON.stringify({ cipher: '3DES-CBC', block_size_bits: 64, ike_version: 1 }, null, 2),
        },
        {
          id: 3,
          rule_id: 'IKE-FLOW-AGGRESSIVE-MODE-PSK',
          category: 'Protocol Architecture',
          severity: 'HIGH',
          title: 'IKEv1 Legacy Protocol Negotiation Detected',
          description:
            'Legacy protocol negotiation detected. IKEv1 transmits initiator ID and hash payloads in the first packet prior to DH key exchange, exposing pre-shared keys to offline dictionary cracking.',
          rfc_reference: 'RFC 2409 Section 5.4',
          remediation_hint: 'Migrate to IKEv2 Main Mode with mutual certificates or asymmetric authentication.',
          evidence_json: JSON.stringify({ exchange_type: 'Aggressive Mode', ike_version: 1, auth_method: 'Pre-Shared Key' }, null, 2),
        },
      ]);

      setThreatMatrixData({
        entries: [
          {
            finding: 'Weak Diffie-Hellman Group 2 (1024-bit MODP) Negotiated',
            severity: 'CRITICAL',
            evidence: 'Group 2 (1024-bit MODP) observed in IKE_SA_INIT proposal',
            impact: 'Discrete log precomputation allows passive adversaries to recover shared secrets (Logjam attack).',
            confidence: 1.0,
            observability: 'OBSERVED',
            reference: 'RFC 8247 Section 2.4 / NIST SP 800-57',
            recommendation: 'Upgrade proposal to MODP-2048 (Group 14) or ECP-256 (Group 19).',
          },
          {
            finding: 'Deprecated 3DES-CBC Encryption Cipher Detected',
            severity: 'HIGH',
            evidence: 'Transform ID 3 (3DES-CBC) with 64-bit block size in proposal payload',
            impact: 'Short block size exposes ciphertext to Sweet32 collision attacks after 32GB of data transfer.',
            confidence: 1.0,
            observability: 'OBSERVED',
            reference: 'RFC 8221 Section 5',
            recommendation: 'Enforce AEAD AES-256-GCM encryption with 128-bit authentication tag.',
          },
          {
            finding: 'IKEv1 Aggressive Mode with Pre-Shared Key (PSK)',
            severity: 'HIGH',
            evidence: 'Exchange Type 4 (Aggressive Mode), PSK authentication payload unencrypted in packet 1',
            impact: 'Initiator identity and auth hash transmitted in clear before DH exchange; susceptible to offline dictionary cracking.',
            confidence: 0.95,
            observability: 'OBSERVED',
            reference: 'RFC 2409 Section 5.4',
            recommendation: 'Migrate to IKEv2 with mutual asymmetric public-key certificates.',
          },
          {
            finding: 'Child SA Encrypted Inside IKE_AUTH',
            severity: 'LOW',
            evidence: 'Payload Type 46 (Encrypted & Authenticated) prevents passive visibility into Child SA proposals',
            impact: 'Passive packet inspection cannot verify ESP ciphers without gateway session keys.',
            confidence: 0.50,
            observability: 'NOT_OBSERVABLE',
            reference: 'RFC 7296 Section 1.2',
            recommendation: 'Verify ESP cipher suite and replay window directly against gateway runtime config.',
          }
        ],
        summary: {
          total_findings: 4,
          critical_count: 1,
          high_count: 2,
          medium_count: 0,
          low_count: 1,
          observed_count: 3,
          inferred_count: 0,
          not_observable_count: 1,
        }
      });

      setMetadataExposureData({
        exposure_level: 'MEDIUM',
        exposure_score: 45.0,
        observable_elements: [
          {
            category: 'Network Endpoints',
            element: 'Public IP Pair (192.168.1.100 <-> 198.51.100.1)',
            impact: 'Exposes communicating gateway entities and geographical routing paths to eavesdroppers.'
          },
          {
            category: 'Signaling Ports',
            element: 'UDP 500 / UDP 4500 (NAT-Traversal Active)',
            impact: 'Identifies presence of IPsec daemon and address-translating intermediate firewall.'
          },
          {
            category: 'Security Parameter Indexes',
            element: 'Initiator SPI (11223344...) / ESP SPI (3a4b5c6d)',
            impact: 'Allows passive correlation of multiple sessions to the same user or security association over time.'
          },
          {
            category: 'Traffic Flow Dynamics',
            element: 'Flow Volume & Sizing Profile (ESP payload lengths)',
            impact: 'Packet sizes and inter-arrival timing expose behavioral application signatures.'
          }
        ],
        confidential_elements: [
          {
            category: 'Application Payload Data',
            protection: 'Encrypted inside ESP payloads (AES-GCM-256 / AES-CBC-256)'
          },
          {
            category: 'Internal Subnets & Private IPs',
            protection: 'Encapsulated within outer IPsec tunnel headers (Tunnel Mode)'
          },
          {
            category: 'User Authentication Credentials',
            protection: 'Protected by Diffie-Hellman Shared Secret (Encrypted IKE_AUTH)'
          }
        ],
        inference_analysis: [
          'Observer identifies continuous site-to-site communication between 192.168.1.100 and 198.51.100.1.',
          'Client resides behind a NAT firewall or cellular carrier-grade NAT (CGNAT).',
          'Traffic timing and packet length distributions expose behavioral application patterns (e.g., interactive Web vs. VoIP).'
        ],
        mitigation_recommendations: [
          'Deploy IPsec Traffic Flow Confidentiality (TFC) padding per RFC 4303 to conceal true packet lengths.',
          'Schedule periodic automated rekeying to cycle ESP SPI values.',
          'Enable constant-rate dummy traffic insertion over sensitive site-to-site tunnels to eliminate flow timing leakage.'
        ]
      });
    }
  }, [assessment]);

  return (
    <div className="min-h-screen bg-[#F6F8FB] dark:bg-[#0B0F19] text-[#0F172A] dark:text-[#F8FAFC] flex font-sans antialiased transition-colors">
      
      {/* Left Navigation Sidebar */}
      <Sidebar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onOpenAuth={() => setAuthModalOpen(true)}
        findingsCount={findings.length}
        isMobileOpen={mobileSidebarOpen}
        onCloseMobile={() => setMobileSidebarOpen(false)}
      />

      {/* Main Operational Stage */}
      <div className="flex-1 flex flex-col min-w-0 h-screen overflow-y-auto">
        
        {/* Top Contextual Navigation Bar */}
        <header className="h-14 bg-white dark:bg-[#111827] border-b border-[#E2E8F0] dark:border-slate-800 px-4 sm:px-6 flex items-center justify-between shrink-0 sticky top-0 z-20 transition-colors">
          <div className="flex items-center gap-3">
            {/* Mobile Hamburger */}
            <button
              onClick={() => setMobileSidebarOpen(true)}
              className="p-1.5 rounded-[7px] text-[#64748B] dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 lg:hidden cursor-pointer"
              title="Open Navigation Menu"
            >
              <Menu className="w-5 h-5" />
            </button>

            <div className="flex items-center gap-2 text-xs font-mono text-[#64748B] dark:text-slate-400">
              <span className="font-semibold text-[#0F172A] dark:text-white">NetSentry Security Center</span>
              <span>/</span>
              <span className="capitalize">{activeTab === 'audit' ? 'Audits' : activeTab}</span>
            </div>
          </div>

          <div className="flex items-center gap-2.5">
            {/* Subtle Engine Active Indicator */}
            <div className="hidden sm:inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-50 dark:bg-emerald-950/40 text-[#059669] dark:text-emerald-400 text-xs font-mono font-medium border border-emerald-200 dark:border-emerald-900/50">
              <span className="w-2 h-2 rounded-full bg-[#059669] animate-pulse" />
              <span>Engine Active (RFC 8247)</span>
            </div>

            {/* Dark / Light Theme Toggle */}
            <ThemeToggle />

            {/* Quick Ingest Button */}
            <button
              onClick={() => setShowIngestBar(!showIngestBar)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-[7px] text-xs font-mono font-medium text-[#0F172A] dark:text-white bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 border border-[#E2E8F0] dark:border-slate-700 transition-colors cursor-pointer"
            >
              <UploadCloud className="w-3.5 h-3.5 text-[#4F46E5] dark:text-indigo-400" />
              <span>{showIngestBar ? 'Close Ingest' : 'Quick Ingest'}</span>
            </button>

            {/* User / Admin Compact Control */}
            {user ? (
              <div className="flex items-center gap-2 pl-1">
                <div className="w-7 h-7 rounded-[6px] bg-[#0F172A] dark:bg-slate-700 text-white flex items-center justify-center text-xs font-mono font-bold">
                  {user.username.charAt(0).toUpperCase()}
                </div>
                <span className="text-xs font-mono text-[#0F172A] dark:text-white hidden md:inline font-semibold">
                  {user.username}
                </span>
              </div>
            ) : (
              <button
                onClick={() => setAuthModalOpen(true)}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-[7px] text-xs font-mono font-medium bg-[#0F172A] dark:bg-indigo-600 text-white hover:bg-slate-800 dark:hover:bg-indigo-500 transition-colors cursor-pointer shadow-2xs"
              >
                <User className="w-3.5 h-3.5" />
                <span>Sign In</span>
              </button>
            )}
          </div>
        </header>

        {/* Collapsible Quick Ingest Bar */}
        {showIngestBar && (
          <div className="p-6 bg-slate-50 dark:bg-[#0F172A] border-b border-[#E2E8F0] dark:border-slate-800 transition-colors">
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
        <main className="flex-1 p-4 sm:p-6 max-w-7xl w-full mx-auto space-y-6 pb-12">
          
          {/* 1. Main Audit Dashboard */}
          {(activeTab === 'audit' || activeTab === 'dashboard') && (
            <>
              {/* AUDIT CONTEXT */}
              <AuditHeader
                assessment={assessment}
                findingsCount={findings.length}
                onDownloadPdf={handleDownloadPdf}
                onDownloadJson={handleDownloadJson}
                downloadingPdf={downloadingPdf}
              />

              {loadingAssessment ? (
                <div className="bg-white dark:bg-[#111827] rounded-[10px] border border-[#E2E8F0] dark:border-slate-800 p-12 text-center flex flex-col items-center justify-center shadow-2xs transition-colors">
                  <Loader2 className="w-8 h-8 text-[#4F46E5] animate-spin mb-3" />
                  <span className="text-xs font-mono font-semibold text-[#0F172A] dark:text-white">
                    Executing Triple-Engine Audit Pipeline...
                  </span>
                  <span className="text-[11px] font-mono text-[#64748B] dark:text-slate-400 mt-1">
                    RFC 8247 Rule Matcher • Stateful FSM State Machine • XGBoost & Tree SHAP Inference
                  </span>
                </div>
              ) : (
                assessment && (
                  <div className="space-y-6">
                    {/* SECURITY POSTURE */}
                    <SecurityPosture
                      assessment={assessment}
                      findings={findings}
                    />

                    {/* SECURITY FINDINGS */}
                    <SecurityFindings
                      findings={findings}
                      onSelectFinding={handleSelectFinding}
                    />

                    {/* 7-COLUMN THREAT MATRIX */}
                    <ThreatMatrix
                      threatMatrixData={threatMatrixData}
                      onSelectFinding={handleSelectFinding}
                    />

                    {/* METADATA EXPOSURE ANALYSIS */}
                    <MetadataExposure
                      metadataExposureData={metadataExposureData}
                    />

                    {/* PROTOCOL FLOW & PACKET DISSECTOR */}
                    <SessionInspector
                      assessment={assessment}
                      findings={findings}
                    />

                    {/* CONFIG REMEDIATION DIFFS */}
                    <RemediationDiff
                      assessment={assessment}
                    />

                    {/* MODEL VALIDATION */}
                    <ModelValidation />

                    {/* MODEL EXPLANATION */}
                    <ModelExplanation
                      assessment={assessment}
                    />

                    {/* TECHNICAL TELEMETRY */}
                    <EngineTelemetry
                      assessment={assessment}
                      sessions={sessions}
                    />
                  </div>
                )
              )}
            </>
          )}

          {/* 2. Dedicated 7-Column Threat Matrix Tab */}
          {activeTab === 'threat-matrix' && (
            <div className="space-y-6">
              <ThreatMatrix
                threatMatrixData={threatMatrixData}
                onSelectFinding={handleSelectFinding}
              />
            </div>
          )}

          {/* 3. Dedicated Traffic Intelligence Tab */}
          {activeTab === 'traffic' && (
            <div className="space-y-6">
              <TrafficIntelligence
                sessionData={sessions[0] || {}}
              />
            </div>
          )}

          {/* 4. Dedicated Metadata Exposure Tab */}
          {activeTab === 'metadata' && (
            <div className="space-y-6">
              <MetadataExposure
                metadataExposureData={metadataExposureData}
              />
            </div>
          )}

          {/* 5. Dedicated Testbed & Lab Tab */}
          {activeTab === 'testbed' && (
            <div className="space-y-6">
              <TestbedLab />
            </div>
          )}

          {/* 6. Dedicated Capture Ingest Tab */}
          {activeTab === 'captures' && (
            <div className="space-y-6">
              <div className="bg-white dark:bg-[#111827] rounded-[10px] border border-[#E2E8F0] dark:border-slate-800 p-5 shadow-2xs transition-colors">
                <h2 className="text-sm font-bold font-mono text-[#0F172A] dark:text-white uppercase tracking-wider mb-1">
                  Network Capture Ingestion & Dissection Engine
                </h2>
                <p className="text-xs text-[#64748B] dark:text-slate-400 font-mono">
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

          {/* 7. Dedicated Findings Catalog Tab */}
          {activeTab === 'findings' && (
            <div className="space-y-6">
              <SecurityFindings
                findings={findings}
                onSelectFinding={handleSelectFinding}
              />
            </div>
          )}

          {/* 8. Dedicated ML Intelligence Tab */}
          {activeTab === 'ml' && (
            <div className="space-y-6">
              <ModelValidation />
              <ModelExplanation assessment={assessment} />
              <MLMetricsPanel />
            </div>
          )}

          {/* 9. Dedicated RFC Library Tab */}
          {activeTab === 'rules' && (
            <div className="space-y-6">
              <RulesCatalog />
            </div>
          )}

          {/* 10. Dedicated Remediation Diffs Tab */}
          {activeTab === 'remediation' && (
            <div className="space-y-6">
              <RemediationDiff assessment={assessment} />
            </div>
          )}

          {/* 11. Dedicated Reports Tab */}
          {activeTab === 'reports' && (
            <div className="space-y-6">
              <div className="bg-white dark:bg-[#111827] rounded-[10px] border border-[#E2E8F0] dark:border-slate-800 p-6 shadow-2xs space-y-4 transition-colors">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#E2E8F0] dark:border-slate-800 pb-4">
                  <div>
                    <h2 className="text-sm font-bold font-mono text-[#0F172A] dark:text-white uppercase tracking-wider">
                      Audit Certification & Executive Export
                    </h2>
                    <p className="text-xs text-[#64748B] dark:text-slate-400 font-mono mt-0.5">
                      Formal assessment report compliant with IETF RFC 8247 & RFC 8221 specifications
                    </p>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={handleDownloadJson}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-[7px] text-xs font-mono font-semibold bg-white dark:bg-[#161E2E] text-[#0F172A] dark:text-white border border-[#E2E8F0] dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors shadow-2xs cursor-pointer"
                    >
                      <FileJson className="w-3.5 h-3.5 text-[#64748B] dark:text-slate-400" />
                      <span>Download JSON Evidence</span>
                    </button>

                    <button
                      onClick={() => handleDownloadPdf('technical')}
                      disabled={downloadingPdf}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-[7px] text-xs font-mono font-semibold bg-white dark:bg-[#161E2E] text-[#0F172A] dark:text-white border border-[#E2E8F0] dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors shadow-2xs cursor-pointer disabled:opacity-50"
                    >
                      {downloadingPdf ? (
                        <Loader2 className="w-3.5 h-3.5 animate-spin text-indigo-500" />
                      ) : (
                        <Download className="w-3.5 h-3.5 text-indigo-500" />
                      )}
                      <span>Export Technical PDF</span>
                    </button>

                    <button
                      onClick={() => handleDownloadPdf('executive')}
                      disabled={downloadingPdf}
                      className="inline-flex items-center gap-1.5 px-4 py-1.5 rounded-[7px] text-xs font-mono font-semibold bg-[#0F172A] dark:bg-indigo-600 hover:bg-slate-800 dark:hover:bg-indigo-500 text-white transition-colors shadow-2xs cursor-pointer disabled:opacity-50"
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

                {/* Executive Summary Statement */}
                <div className="p-4 rounded-[8px] bg-[#F6F8FB] dark:bg-[#161E2E] border border-[#E2E8F0] dark:border-slate-800 space-y-2 transition-colors">
                  <span className="text-[10px] uppercase font-mono font-bold text-[#64748B] dark:text-slate-400 block">
                    Executive Summary Statement
                  </span>
                  <p className="text-xs text-[#0F172A] dark:text-slate-200 font-sans leading-relaxed">
                    {assessment?.executive_summary}
                  </p>
                </div>

                {/* Sign-Off Checklist */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono pt-2">
                  <div className="p-3 bg-white dark:bg-[#111827] border border-[#E2E8F0] dark:border-slate-800 rounded-[8px]">
                    <span className="text-[10px] text-[#64748B] dark:text-slate-400 block">Overall Risk Rating</span>
                    <span className="text-sm font-extrabold text-[#DC2626] dark:text-rose-400 mt-0.5 block">
                      {assessment?.risk_level} ({assessment?.overall_score}/100)
                    </span>
                  </div>

                  <div className="p-3 bg-white dark:bg-[#111827] border border-[#E2E8F0] dark:border-slate-800 rounded-[8px]">
                    <span className="text-[10px] text-[#64748B] dark:text-slate-400 block">Violations Count</span>
                    <span className="text-sm font-extrabold text-[#D97706] dark:text-amber-400 mt-0.5 block">
                      {findings.length} Flagged Parameters
                    </span>
                  </div>

                  <div className="p-3 bg-white dark:bg-[#111827] border border-[#E2E8F0] dark:border-slate-800 rounded-[8px]">
                    <span className="text-[10px] text-[#64748B] dark:text-slate-400 block">Engine Conformance</span>
                    <span className="text-sm font-extrabold text-[#059669] dark:text-emerald-400 mt-0.5 block">
                      RFC 8247 Certified
                    </span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* 8. Dedicated Settings Tab */}
          {activeTab === 'settings' && (
            <div className="space-y-6">
              {/* Theme Settings Card */}
              <div className="bg-white dark:bg-[#111827] rounded-[10px] border border-[#E2E8F0] dark:border-slate-800 p-6 shadow-2xs space-y-4 font-mono text-xs transition-colors">
                <div className="border-b border-[#E2E8F0] dark:border-slate-800 pb-3 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Palette className="w-4 h-4 text-[#4F46E5] dark:text-indigo-400" />
                    <div>
                      <h2 className="text-sm font-bold text-[#0F172A] dark:text-white uppercase tracking-wider">
                        Appearance & Operations Environment
                      </h2>
                      <p className="text-xs text-[#64748B] dark:text-slate-400 font-mono mt-0.5">
                        Toggle between Executive Audit (Light) and SOC Night Ops (Dark) modes
                      </p>
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-1">
                  <button
                    onClick={() => setTheme('light')}
                    className={`p-4 rounded-[8px] border text-left transition-all cursor-pointer ${
                      theme === 'light'
                        ? 'border-[#4F46E5] bg-indigo-50/50 dark:bg-indigo-950/30 shadow-2xs'
                        : 'border-[#E2E8F0] dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 bg-white dark:bg-[#161E2E]'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <Sun className="w-5 h-5 text-amber-500" />
                      {theme === 'light' && <span className="text-[10px] font-bold text-[#4F46E5] dark:text-indigo-400">ACTIVE</span>}
                    </div>
                    <div className="mt-2 text-sm font-bold text-[#0F172A] dark:text-white">
                      Enterprise Audit
                    </div>
                    <div className="text-[11px] text-[#64748B] dark:text-slate-400 mt-0.5 font-sans">
                      Clean daylight theme calibrated for executive briefings and projector presentations.
                    </div>
                  </button>

                  <button
                    onClick={() => setTheme('dark')}
                    className={`p-4 rounded-[8px] border text-left transition-all cursor-pointer ${
                      theme === 'dark'
                        ? 'border-[#4F46E5] bg-indigo-50/50 dark:bg-indigo-950/30 shadow-2xs'
                        : 'border-[#E2E8F0] dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 bg-white dark:bg-[#161E2E]'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <Moon className="w-5 h-5 text-indigo-400" />
                      {theme === 'dark' && <span className="text-[10px] font-bold text-[#4F46E5] dark:text-indigo-400">ACTIVE</span>}
                    </div>
                    <div className="mt-2 text-sm font-bold text-[#0F172A] dark:text-white">
                      SOC Night Ops
                    </div>
                    <div className="text-[11px] text-[#64748B] dark:text-slate-400 mt-0.5 font-sans">
                      Deep slate aesthetic calibrated for 24/7 dark-room SOC telemetry monitoring.
                    </div>
                  </button>

                  <button
                    onClick={() => setTheme('system')}
                    className={`p-4 rounded-[8px] border text-left transition-all cursor-pointer ${
                      theme === 'system'
                        ? 'border-[#4F46E5] bg-indigo-50/50 dark:bg-indigo-950/30 shadow-2xs'
                        : 'border-[#E2E8F0] dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 bg-white dark:bg-[#161E2E]'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <Monitor className="w-5 h-5 text-slate-500" />
                      {theme === 'system' && <span className="text-[10px] font-bold text-[#4F46E5] dark:text-indigo-400">ACTIVE</span>}
                    </div>
                    <div className="mt-2 text-sm font-bold text-[#0F172A] dark:text-white">
                      System Preference
                    </div>
                    <div className="text-[11px] text-[#64748B] dark:text-slate-400 mt-0.5 font-sans">
                      Automatically syncs with your operating system color scheme preference.
                    </div>
                  </button>
                </div>
              </div>

              {/* Policy Settings Card */}
              <div className="bg-white dark:bg-[#111827] rounded-[10px] border border-[#E2E8F0] dark:border-slate-800 p-6 shadow-2xs space-y-5 font-mono text-xs transition-colors">
                <div className="border-b border-[#E2E8F0] dark:border-slate-800 pb-3 flex items-center justify-between">
                  <div>
                    <h2 className="text-sm font-bold text-[#0F172A] dark:text-white uppercase tracking-wider">
                      SOC Engine & Audit Policies
                    </h2>
                    <p className="text-xs text-[#64748B] dark:text-slate-400 font-mono mt-0.5">
                      Operational runtime flags and RFC compliance thresholds
                    </p>
                  </div>
                  <span className="px-2 py-0.5 bg-emerald-50 dark:bg-emerald-950/40 text-[#059669] dark:text-emerald-400 border border-emerald-200 dark:border-emerald-900/50 rounded-[5px] text-[10px] font-bold">
                    Active Engine (Port 8000)
                  </span>
                </div>

                <div className="space-y-3">
                  <div className="p-3.5 rounded-[8px] bg-[#F6F8FB] dark:bg-[#161E2E] border border-[#E2E8F0] dark:border-slate-800 flex items-center justify-between">
                    <div>
                      <span className="text-[#0F172A] dark:text-white font-bold block">Enforce RFC 8247 Baseline</span>
                      <span className="text-[11px] text-[#64748B] dark:text-slate-400 block mt-0.5">
                        Prohibit Diffie-Hellman groups below 2048-bit (MODP-1024, MODP-768)
                      </span>
                    </div>
                    <span className="px-2 py-1 bg-emerald-50 dark:bg-emerald-950/40 text-[#059669] dark:text-emerald-400 border border-emerald-200 dark:border-emerald-900/50 rounded-[6px] text-[11px] font-bold">
                      ENFORCED
                    </span>
                  </div>

                  <div className="p-3.5 rounded-[8px] bg-[#F6F8FB] dark:bg-[#161E2E] border border-[#E2E8F0] dark:border-slate-800 flex items-center justify-between">
                    <div>
                      <span className="text-[#0F172A] dark:text-white font-bold block">Enforce RFC 8221 ESP Ciphers</span>
                      <span className="text-[11px] text-[#64748B] dark:text-slate-400 block mt-0.5">
                        Prohibit legacy 64-bit block ciphers (3DES-CBC, DES) to prevent Sweet32 attacks
                      </span>
                    </div>
                    <span className="px-2 py-1 bg-emerald-50 dark:bg-emerald-950/40 text-[#059669] dark:text-emerald-400 border border-emerald-200 dark:border-emerald-900/50 rounded-[6px] text-[11px] font-bold">
                      ENFORCED
                    </span>
                  </div>

                  <div className="p-3.5 rounded-[8px] bg-[#F6F8FB] dark:bg-[#161E2E] border border-[#E2E8F0] dark:border-slate-800 flex items-center justify-between">
                    <div>
                      <span className="text-[#0F172A] dark:text-white font-bold block">Tree SHAP Feature Attribution</span>
                      <span className="text-[11px] text-[#64748B] dark:text-slate-400 block mt-0.5">
                        Polynomial-time Shapley calculation on supervised XGBoost risk classification
                      </span>
                    </div>
                    <span className="px-2 py-1 bg-indigo-50 dark:bg-indigo-950/40 text-[#4F46E5] dark:text-indigo-400 border border-indigo-200 dark:border-indigo-900/50 rounded-[6px] text-[11px] font-bold">
                      ENABLED
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
    <ThemeProvider>
      <AuthProvider>
        <DashboardContent />
      </AuthProvider>
    </ThemeProvider>
  );
}
