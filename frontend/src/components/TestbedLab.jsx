import React, { useState } from 'react';
import { 
  Server, 
  Copy, 
  Check, 
  Download, 
  Sliders, 
  Layers, 
  Code, 
  ShieldCheck, 
  ShieldAlert,
  Terminal,
  FileCode
} from 'lucide-react';
import axios from 'axios';

const SUPPORTED_DH_GROUPS = [
  { num: 1, name: 'Group 1 (768-bit MODP - Deprecated)', bits: 64, status: 'deprecated' },
  { num: 2, name: 'Group 2 (1024-bit MODP - Deprecated)', bits: 80, status: 'deprecated' },
  { num: 5, name: 'Group 5 (1536-bit MODP - Deprecated)', bits: 96, status: 'deprecated' },
  { num: 14, name: 'Group 14 (2048-bit MODP - Standard)', bits: 112, status: 'standard' },
  { num: 19, name: 'Group 19 (256-bit ECP - Recommended)', bits: 128, status: 'recommended' },
  { num: 20, name: 'Group 20 (384-bit ECP - Recommended)', bits: 192, status: 'recommended' },
  { num: 31, name: 'Group 31 (Curve25519 - Recommended)', bits: 128, status: 'recommended' },
];

const TRAFFIC_PROFILES = [
  { id: 'Web', name: 'Web Browsing (HTTP/HTTPS)', desc: 'Bursty request-response patterns with high variance' },
  { id: 'VoIP', name: 'VoIP / Audio Stream', desc: 'Symmetric ~180-byte periodic UDP frames with minimal jitter' },
  { id: 'Video', name: 'Video Streaming', desc: 'Heavy downlink bandwidth with periodic keyframe spikes' },
  { id: 'Messaging-like', name: 'Instant Messaging', desc: 'Sporadic tiny packets with long idle inter-arrival times' },
  { id: 'Email-like', name: 'Email Sync (IMAP/SMTP)', desc: 'Periodic background check with sporadic burst transfers' },
  { id: 'ICMP', name: 'ICMP Keepalive / Ping', desc: 'Small strictly periodic diagnostic echo frames' },
  { id: 'Bulk/Data', name: 'Bulk Data Transfer', desc: 'Sustained full-MTU packet saturation (1420 bytes)' },
];

export default function TestbedLab() {
  const [ikeVer, setIkeVer] = useState(2);
  const [cipher, setCipher] = useState('AES-256-GCM');
  const [dhGroup, setDhGroup] = useState(19);
  const [mode, setMode] = useState('tunnel');
  const [ipVersion, setIpVersion] = useState('IPv4');
  const [pfs, setPfs] = useState(true);

  const [activePlatform, setActivePlatform] = useState('strongswan'); // 'strongswan' or 'cisco'
  const [copied, setCopied] = useState(false);

  // Traffic download state
  const [selectedProfile, setSelectedProfile] = useState('Web');
  const [downloadingPcap, setDownloadingPcap] = useState(false);

  // Generate strongSwan config dynamically
  const getStrongswanConfig = () => {
    const isAggr = ikeVer === 1 ? 'no' : 'no';
    const cSwan = cipher.toLowerCase().replace('-', '').replace('gcm', 'gcm16');
    const dhSlug = dhGroup === 19 ? 'ecp256' : (dhGroup === 20 ? 'ecp384' : (dhGroup === 31 ? 'curve25519' : `modp${dhGroup === 1 ? 768 : (dhGroup === 2 ? 1024 : (dhGroup === 5 ? 1536 : 2048))}`));
    const proposal = cipher.includes('GCM') 
      ? `${cSwan}-prfsha256-${dhSlug}` 
      : `${cSwan}-sha256-${dhSlug}`;

    return `# strongSwan swanctl.conf - NetSentry Testbed Configuration
# Mode: ${mode.toUpperCase()} | IP: ${ipVersion} | DH: Group ${dhGroup}
connections {
    netsentry-testbed {
        version = ${ikeVer}
        proposals = ${proposal}
        aggressive = ${isAggr}
        local_addrs = ${ipVersion === 'IPv6' ? '2001:db8::1' : '192.168.1.100'}
        remote_addrs = ${ipVersion === 'IPv6' ? '2001:db8::2' : '198.51.100.1'}

        local {
            auth = psk
            id = vpn-client@netsentry.internal
        }
        remote {
            auth = psk
        }

        children {
            traffic-flow {
                esp_proposals = ${cSwan}${pfs ? `-${dhSlug}` : ''}
                mode = ${mode}
                local_ts = ${ipVersion === 'IPv6' ? '2001:db8:1::/64' : '10.1.0.0/24'}
                remote_ts = ${ipVersion === 'IPv6' ? '2001:db8:2::/64' : '10.2.0.0/24'}
                dpd_action = restart
            }
        }
    }
}

secrets {
    ike-netsentry {
        secret = "NetSentryTestbedPSKSecret2026!"
    }
}`;
  };

  // Generate Cisco IOS-XE template dynamically
  const getCiscoConfig = () => {
    const encCisco = cipher.includes('256-GCM') ? 'aes-gcm-256' : (cipher.includes('128-GCM') ? 'aes-gcm-128' : 'aes 256');
    const isGcm = cipher.includes('GCM');

    if (ikeVer === 2) {
      return `! Cisco IOS-XE Configuration Template - NetSentry Testbed
! Session: TESTBED-${mode.toUpperCase()} | DH: Group ${dhGroup}
crypto ikev2 proposal NETSENTRY_PROP
 encryption ${encCisco}
 prf sha256
 group ${dhGroup}
!
crypto ikev2 policy NETSENTRY_POL
 proposal NETSENTRY_PROP
!
crypto ipsec transform-set TS_TESTBED ${isGcm ? 'esp-gcm 256' : 'esp-aes esp-sha256-hmac'}
 mode ${mode}
!
crypto ipsec profile NETSENTRY_PROFILE
 set transform-set TS_TESTBED
 ${pfs ? `set pfs group${dhGroup}` : '! PFS disabled'}
 set ikev2-policy NETSENTRY_POL
!
interface Tunnel100
 ip address 10.255.255.1 255.255.255.252
 tunnel source GigabitEthernet0/0
 tunnel destination 198.51.100.1
 tunnel mode ipsec ${ipVersion === 'IPv6' ? 'ipv6' : 'ipv4'}
 tunnel protection ipsec profile NETSENTRY_PROFILE`;
    } else {
      return `! Cisco IOS-XE IKEv1 Legacy Template - NetSentry Testbed
crypto isakmp policy 10
 encr ${cipher.includes('3DES') ? '3des' : 'aes 256'}
 hash sha
 authentication pre-share
 group ${dhGroup}
 lifetime 86400
!
crypto ipsec transform-set LEGACY_TS esp-3des esp-md5-hmac
 mode ${mode}
!
crypto map NETSENTRY_MAP 10 ipsec-isakmp
 set peer 198.51.100.1
 set transform-set LEGACY_TS
 ${pfs ? `set pfs group${dhGroup}` : '! PFS disabled'}
 match address 101`;
    }
  };

  const handleCopy = () => {
    const text = activePlatform === 'strongswan' ? getStrongswanConfig() : getCiscoConfig();
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadPcap = async () => {
    setDownloadingPcap(true);
    try {
      const res = await axios.post('/api/testbed/generate-traffic', {
        scenario: ikeVer === 2 ? 'IKEV2_ESTABLISHED' : 'IKEV1_MAIN_MODE',
        profile: selectedProfile,
        packet_count: 40,
      }, { responseType: 'blob' });

      const url = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `netsentry_testbed_${selectedProfile.toLowerCase()}_ikev${ikeVer}.pcap`);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (e) {
      console.error("Traffic PCAP download failed", e);
    } finally {
      setDownloadingPcap(false);
    }
  };

  return (
    <div className="bg-white dark:bg-[#111827] rounded-[10px] border border-[#E2E8F0] dark:border-slate-800 shadow-2xs overflow-hidden">
      {/* Header */}
      <div className="p-5 border-b border-[#E2E8F0] dark:border-slate-800">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 border border-indigo-500/20">
                TESTBED & LAB ENVIRONMENT
              </span>
              <span className="text-xs text-[#64748B] dark:text-slate-400 font-mono">
                SIH26160 Deployment Matrix & Synthetic Traffic
              </span>
            </div>
            <h2 className="text-lg font-bold text-[#0F172A] dark:text-[#F8FAFC]">
              IPsec Deployment Testbed & Appliance Templates
            </h2>
          </div>

          <div className="text-xs font-mono text-slate-500 dark:text-slate-400">
            Supported DH Groups: <b className="text-indigo-600 dark:text-indigo-400">1, 2, 5, 14, 19, 20, 31</b>
          </div>
        </div>
      </div>

      <div className="p-5 space-y-6">
        {/* Top Controls: Matrix Configuration Selectors */}
        <div className="p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-900/40">
          <div className="flex items-center gap-2 mb-3">
            <Sliders className="w-4 h-4 text-indigo-500" />
            <span className="text-xs font-mono font-bold uppercase text-slate-700 dark:text-slate-300">
              Interactive Testbed Matrix Parameters
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 text-xs font-mono">
            {/* IKE Version */}
            <div>
              <label className="text-[10px] uppercase text-slate-500 block mb-1">IKE Version</label>
              <select
                value={ikeVer}
                onChange={(e) => setIkeVer(parseInt(e.target.value))}
                className="w-full px-2 py-1.5 rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-800 dark:text-slate-200"
              >
                <option value={2}>IKEv2 (Modern)</option>
                <option value={1}>IKEv1 (Legacy)</option>
              </select>
            </div>

            {/* Cipher */}
            <div>
              <label className="text-[10px] uppercase text-slate-500 block mb-1">Cipher Algorithm</label>
              <select
                value={cipher}
                onChange={(e) => setCipher(e.target.value)}
                className="w-full px-2 py-1.5 rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-800 dark:text-slate-200"
              >
                <option value="AES-256-GCM">AES-256-GCM (AEAD)</option>
                <option value="AES-128-GCM">AES-128-GCM (AEAD)</option>
                <option value="AES-256-CBC">AES-256-CBC</option>
                <option value="AES-128-CBC">AES-128-CBC</option>
                <option value="3DES-CBC">3DES-CBC (Insecure)</option>
              </select>
            </div>

            {/* DH Group */}
            <div>
              <label className="text-[10px] uppercase text-slate-500 block mb-1">Diffie-Hellman Group</label>
              <select
                value={dhGroup}
                onChange={(e) => setDhGroup(parseInt(e.target.value))}
                className="w-full px-2 py-1.5 rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-800 dark:text-slate-200"
              >
                {SUPPORTED_DH_GROUPS.map((g) => (
                  <option key={g.num} value={g.num}>
                    Group {g.num} ({g.bits}b) {g.status === 'deprecated' ? '⚠️' : '✓'}
                  </option>
                ))}
              </select>
            </div>

            {/* IPsec Mode */}
            <div>
              <label className="text-[10px] uppercase text-slate-500 block mb-1">IPsec Mode</label>
              <select
                value={mode}
                onChange={(e) => setMode(e.target.value)}
                className="w-full px-2 py-1.5 rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-800 dark:text-slate-200"
              >
                <option value="tunnel">Tunnel Mode</option>
                <option value="transport">Transport Mode</option>
              </select>
            </div>

            {/* IP Version */}
            <div>
              <label className="text-[10px] uppercase text-slate-500 block mb-1">IP Version</label>
              <select
                value={ipVersion}
                onChange={(e) => setIpVersion(e.target.value)}
                className="w-full px-2 py-1.5 rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-800 dark:text-slate-200"
              >
                <option value="IPv4">IPv4 Native</option>
                <option value="IPv6">IPv6 Tunnel</option>
              </select>
            </div>

            {/* PFS */}
            <div>
              <label className="text-[10px] uppercase text-slate-500 block mb-1">Forward Secrecy (PFS)</label>
              <select
                value={pfs ? 'true' : 'false'}
                onChange={(e) => setPfs(e.target.value === 'true')}
                className="w-full px-2 py-1.5 rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-800 dark:text-slate-200"
              >
                <option value="true">Enabled (DH Rekey)</option>
                <option value="false">Disabled</option>
              </select>
            </div>
          </div>
        </div>

        {/* Configuration Snippet Generator */}
        <div className="rounded-lg border border-slate-200 dark:border-slate-800 overflow-hidden">
          <div className="bg-slate-50 dark:bg-slate-900 px-4 py-2.5 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <button
                onClick={() => setActivePlatform('strongswan')}
                className={`px-3 py-1 rounded text-xs font-mono font-semibold transition-colors cursor-pointer ${
                  activePlatform === 'strongswan'
                    ? 'bg-indigo-600 text-white'
                    : 'bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300'
                }`}
              >
                strongSwan (swanctl.conf)
              </button>
              <button
                onClick={() => setActivePlatform('cisco')}
                className={`px-3 py-1 rounded text-xs font-mono font-semibold transition-colors cursor-pointer ${
                  activePlatform === 'cisco'
                    ? 'bg-indigo-600 text-white'
                    : 'bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300'
                }`}
              >
                Cisco IOS-XE Template
              </button>
            </div>

            <button
              onClick={handleCopy}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-mono text-slate-600 dark:text-slate-300 hover:text-indigo-600 dark:hover:text-indigo-400 cursor-pointer"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied!' : 'Copy Config'}</span>
            </button>
          </div>

          <pre className="p-4 bg-slate-950 text-slate-200 font-mono text-xs overflow-x-auto leading-relaxed max-h-72">
            {activePlatform === 'strongswan' ? getStrongswanConfig() : getCiscoConfig()}
          </pre>
        </div>

        {/* Synthetic Traffic PCAP Generator Section */}
        <div className="p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <FileCode className="w-4 h-4 text-indigo-500" />
                <span className="text-xs font-mono font-bold uppercase text-slate-700 dark:text-slate-300">
                  Generate Synthetic Testbed PCAP
                </span>
              </div>
              <p className="text-xs font-mono text-slate-500">
                Generate and download valid in-memory binary PCAP traces for any of the 7 supported traffic profiles.
              </p>
            </div>

            <div className="flex items-center gap-2">
              <select
                value={selectedProfile}
                onChange={(e) => setSelectedProfile(e.target.value)}
                className="text-xs font-mono px-3 py-1.5 rounded border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-900 text-slate-800 dark:text-slate-200"
              >
                {TRAFFIC_PROFILES.map((tp) => (
                  <option key={tp.id} value={tp.id}>
                    {tp.name}
                  </option>
                ))}
              </select>

              <button
                onClick={handleDownloadPcap}
                disabled={downloadingPcap}
                className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded text-xs font-mono font-bold bg-indigo-600 hover:bg-indigo-700 text-white cursor-pointer disabled:opacity-50"
              >
                <Download className="w-3.5 h-3.5" />
                <span>{downloadingPcap ? 'Generating...' : 'Download PCAP'}</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
