import React, { useState, useEffect } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import Navbar from './components/Navbar';
import UploadZone from './components/UploadZone';
import ScoreGauge from './components/ScoreGauge';
import FindingsTable from './components/FindingsTable';
import RemediationDiff from './components/RemediationDiff';
import MLMetricsPanel from './components/MLMetricsPanel';
import RulesCatalog from './components/RulesCatalog';
import AuthModal from './components/AuthModal';
import api from './api';
import { Download, Loader2, Sparkles, FileText, CheckCircle2, Shield } from 'lucide-react';

function DashboardContent() {
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState('audit');
  const [authModalOpen, setAuthModalOpen] = useState(false);

  const [currentJob, setCurrentJob] = useState(null);
  const [assessment, setAssessment] = useState(null);
  const [findings, setFindings] = useState([]);
  const [sessions, setSessions] = useState([]);
  const [loadingAssessment, setLoadingAssessment] = useState(false);
  const [downloadingPdf, setDownloadingPdf] = useState(false);

  // Load audit data once a job completes
  const handleJobCompleted = async (jobId) => {
    setLoadingAssessment(true);
    try {
      const assessRes = await api.get(`/assessments/${jobId}`);
      setAssessment(assessRes.data);

      const findingsRes = await api.get(`/ingest/jobs/${jobId}/findings`);
      setFindings(findingsRes.data || []);

      const sessionsRes = await api.get(`/ingest/jobs/${jobId}/sessions`);
      setSessions(sessionsRes.data || []);
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
            'Diffie-Hellman Group 2 uses a 1024-bit prime modulus which is susceptible to precomputation attacks (Logjam) and deprecated by RFC 8247.',
          rfc_reference: 'RFC 8247 Section 2.4',
          remediation_hint: 'Upgrade proposal to MODP 2048 (Group 14) or Curve25519 (Group 31).',
          evidence_json: JSON.stringify({ dh_group_num: 2, dh_group_name: 'Group 2 (1024-bit MODP)' }),
        },
        {
          id: 2,
          rule_id: 'IKE-CRYPTO-DEPRECATED-CIPHER-3DES',
          category: 'Cryptography',
          severity: 'HIGH',
          title: 'Deprecated 3DES-CBC Encryption Cipher',
          description:
            'Triple-DES uses a 64-bit block size vulnerable to Sweet32 birthday collision attacks after transferring high-volume traffic.',
          rfc_reference: 'RFC 8221 Section 5',
          remediation_hint: 'Enforce AEAD AES-GCM-256 encryption proposals.',
          evidence_json: JSON.stringify({ cipher: '3DES-CBC', block_size_bits: 64 }),
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
          evidence_json: JSON.stringify({ exchange_type: 'Aggressive Mode', ike_version: 1 }),
        },
      ]);
    }
  }, []);

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 flex flex-col font-sans">
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onOpenAuth={() => setAuthModalOpen(true)}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        
        {/* Banner with PDF Export Button */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 bg-white p-5 rounded-2xl border border-slate-200 shadow-xs">
          <div>
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse" />
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                Live VPN Security Audit Engine
              </span>
            </div>
            <h1 className="text-xl font-bold text-slate-900 mt-1">
              IPsec Protocol Security Assessment & Remediation
            </h1>
          </div>

          <div className="flex items-center gap-3 w-full sm:w-auto">
            {assessment && (
              <button
                onClick={handleDownloadPdf}
                disabled={downloadingPdf}
                className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-4 py-2.5 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-bold rounded-xl shadow-xs transition-all cursor-pointer disabled:opacity-50"
              >
                {downloadingPdf ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Download className="w-4 h-4" />
                )}
                <span>Export Executive PDF Audit Report</span>
              </button>
            )}
          </div>
        </div>

        {/* Tab 1: Security Audit Dashboard */}
        {activeTab === 'audit' && (
          <div className="space-y-8">
            <UploadZone
              onJobStarted={(job) => setCurrentJob(job)}
              onJobCompleted={handleJobCompleted}
              onOpenAuth={() => setAuthModalOpen(true)}
            />

            {loadingAssessment ? (
              <div className="bg-white rounded-2xl border border-slate-200 p-12 text-center flex flex-col items-center justify-center shadow-xs">
                <Loader2 className="w-10 h-10 text-indigo-600 animate-spin mb-3" />
                <span className="text-sm font-semibold text-slate-800">Generating Explainable Risk Assessment...</span>
                <span className="text-xs text-slate-400 mt-1">Running RiskScorer and RemediationGenerator algorithms</span>
              </div>
            ) : (
              assessment && (
                <>
                  <ScoreGauge assessment={assessment} findings={findings} />
                  <FindingsTable findings={findings} />
                  <RemediationDiff assessment={assessment} />
                </>
              )
            )}
          </div>
        )}

        {/* Tab 2: Machine Learning Hub & SHAP */}
        {activeTab === 'ml' && <MLMetricsPanel />}

        {/* Tab 3: RFC Standards Catalog */}
        {activeTab === 'rules' && <RulesCatalog />}

      </main>

      {/* Footer */}
      <footer className="bg-white border-t border-slate-200 py-6 mt-12 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-indigo-600" />
            <span className="font-semibold text-slate-700">NetSentry AI</span>
            <span>— Smart India Hackathon 2026 (Problem Statement SIH26160)</span>
          </div>
          <div>
            <span>Developed by <b>Team Code Craft</b> • Hardened for RFC 4301, 7296, 8247, 8221 Compliance</span>
          </div>
        </div>
      </footer>

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
