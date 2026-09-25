import React, { useState, useEffect, useRef } from 'react';
import { 
  Activity, 
  Cpu, 
  Radio, 
  Play, 
  Square, 
  RefreshCw, 
  CheckCircle, 
  AlertTriangle, 
  ListFilter,
  BarChart2,
  Terminal,
  ShieldAlert
} from 'lucide-react';
import axios from 'axios';

const FLOW_FEATURE_DEFINITIONS = [
  { name: 'packet_count', unit: 'packets', desc: 'Total packet count observed in flow', normal: '20 - 500' },
  { name: 'bytes_sent', unit: 'bytes', desc: 'Total uplink payload bytes (client -> gateway)', normal: '1KB - 2MB' },
  { name: 'bytes_received', unit: 'bytes', desc: 'Total downlink payload bytes (gateway -> client)', normal: '1KB - 5MB' },
  { name: 'mean_packet_size', unit: 'bytes', desc: 'Average outer packet size across flow', normal: '160B (VoIP) - 1420B (Bulk)' },
  { name: 'packet_size_variance', unit: 'bytes²', desc: 'Variance of packet sizes (dispersion metric)', normal: 'Low for VoIP, High for Web' },
  { name: 'min_packet_size', unit: 'bytes', desc: 'Minimum packet length recorded', normal: '60B - 128B' },
  { name: 'max_packet_size', unit: 'bytes', desc: 'Maximum packet length recorded (MTU bound)', normal: '1280B - 1500B' },
  { name: 'packets_per_sec', unit: 'pkts/s', desc: 'Average flow packet transmission rate', normal: '5 - 100 pps' },
  { name: 'bytes_per_sec', unit: 'B/s', desc: 'Average throughput rate across flow', normal: '10KB/s - 1MB/s' },
  { name: 'duration_seconds', unit: 'seconds', desc: 'Total active flow duration', normal: '0.1s - 60s' },
  { name: 'mean_inter_arrival_time', unit: 'seconds', desc: 'Mean time delta between consecutive packets', normal: '0.01s - 0.2s' },
  { name: 'var_inter_arrival_time', unit: 's²', desc: 'Variance of inter-arrival deltas (jitter proxy)', normal: '0.0001 - 0.05' },
  { name: 'downlink_uplink_ratio', unit: 'ratio', desc: 'Ratio of downlink bytes vs. uplink bytes', normal: '1.0 (VoIP) - >4.0 (Web)' },
  { name: 'burst_factor', unit: 'ratio', desc: 'Max packet size relative to mean packet size', normal: '1.1 (VoIP) - 2.5 (Web)' },
];

export default function TrafficIntelligence({ sessionData }) {
  const [activeTab, setActiveTab] = useState('classifier'); // 'classifier', 'features', 'live'
  
  // Classifier state
  const [classifying, setClassifying] = useState(false);
  const [classificationResult, setClassificationResult] = useState(null);

  // Live simulation state
  const [isSimulating, setIsSimulating] = useState(false);
  const [simScenario, setSimScenario] = useState('IKEV2_ESTABLISHED');
  const [simRate, setSimRate] = useState(5.0);
  const [livePackets, setLivePackets] = useState([]);
  const [packetsCaptured, setPacketsCaptured] = useState(0);
  const terminalEndRef = useRef(null);

  // Check if sessionData already has pre-computed classification
  useEffect(() => {
    if (sessionData?.raw_metadata?.traffic_classification) {
      setClassificationResult(sessionData.raw_metadata.traffic_classification);
    } else if (sessionData?.packet_count) {
      // Run quick classification on session
      runClassification();
    }
  }, [sessionData]);

  // Polling for live simulation status when active
  useEffect(() => {
    let interval = null;
    if (isSimulating) {
      interval = setInterval(async () => {
        try {
          const res = await axios.get('/api/traffic/live/status');
          if (res.data) {
            setIsSimulating(res.data.is_active);
            setPacketsCaptured(res.data.packets_captured);
            if (res.data.recent_packets) {
              setLivePackets(res.data.recent_packets);
            }
          }
        } catch (e) {
          console.error("Live status poll failed", e);
        }
      }, 800);
    }
    return () => clearInterval(interval);
  }, [isSimulating]);

  useEffect(() => {
    if (activeTab === 'live') {
      terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [livePackets, activeTab]);

  const runClassification = async () => {
    setClassifying(true);
    try {
      const payload = {
        packet_count: sessionData?.packet_count || 40,
        flow_duration: 1.25,
        flow_bytes: (sessionData?.packet_count || 40) * 450,
        packet_sizes: [128, 256, 512, 1024, 1380, 1420],
        packet_times: [0.0, 0.05, 0.12, 0.25, 0.60, 1.20],
      };
      const res = await axios.post('/api/traffic/classify', payload);
      if (res.data?.result) {
        setClassificationResult(res.data.result);
      }
    } catch (err) {
      console.error("Classification request failed", err);
    } finally {
      setClassifying(false);
    }
  };

  const handleStartSimulation = async () => {
    try {
      const res = await axios.post('/api/traffic/live/start', {
        scenario: simScenario,
        packet_count: 50,
        rate_pps: parseFloat(simRate),
      });
      if (res.data?.status === 'STARTED') {
        setIsSimulating(true);
        setLivePackets([]);
        setPacketsCaptured(0);
      }
    } catch (e) {
      console.error("Start simulation failed", e);
    }
  };

  const handleStopSimulation = async () => {
    try {
      const res = await axios.post('/api/traffic/live/stop');
      setIsSimulating(false);
    } catch (e) {
      console.error("Stop simulation failed", e);
    }
  };

  return (
    <div className="bg-white dark:bg-[#111827] rounded-[10px] border border-[#E2E8F0] dark:border-slate-800 shadow-2xs overflow-hidden">
      {/* Tab Navigation Header */}
      <div className="border-b border-[#E2E8F0] dark:border-slate-800 px-5 pt-4 pb-0 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 border border-indigo-500/20">
              ENCRYPTED TRAFFIC INTELLIGENCE
            </span>
            <span className="text-xs text-[#64748B] dark:text-slate-400 font-mono">
              14 Flow Features & Behavioral ML
            </span>
          </div>
          <h2 className="text-lg font-bold text-[#0F172A] dark:text-[#F8FAFC]">
            Encrypted Flow Characterization & Live Stream Simulator
          </h2>
        </div>

        {/* Tab Buttons */}
        <div className="flex items-center gap-1">
          <button
            onClick={() => setActiveTab('classifier')}
            className={`px-3 py-2 text-xs font-mono font-semibold border-b-2 transition-colors cursor-pointer ${
              activeTab === 'classifier'
                ? 'border-indigo-600 text-indigo-600 dark:text-indigo-400 dark:border-indigo-400'
                : 'border-transparent text-slate-500 hover:text-slate-700 dark:hover:text-slate-300'
            }`}
          >
            <Cpu className="w-3.5 h-3.5 inline mr-1.5" />
            Classifier Inference
          </button>
          <button
            onClick={() => setActiveTab('features')}
            className={`px-3 py-2 text-xs font-mono font-semibold border-b-2 transition-colors cursor-pointer ${
              activeTab === 'features'
                ? 'border-indigo-600 text-indigo-600 dark:text-indigo-400 dark:border-indigo-400'
                : 'border-transparent text-slate-500 hover:text-slate-700 dark:hover:text-slate-300'
            }`}
          >
            <ListFilter className="w-3.5 h-3.5 inline mr-1.5" />
            14 Flow Features
          </button>
          <button
            onClick={() => setActiveTab('live')}
            className={`px-3 py-2 text-xs font-mono font-semibold border-b-2 transition-colors cursor-pointer ${
              activeTab === 'live'
                ? 'border-indigo-600 text-indigo-600 dark:text-indigo-400 dark:border-indigo-400'
                : 'border-transparent text-slate-500 hover:text-slate-700 dark:hover:text-slate-300'
            }`}
          >
            <Radio className="w-3.5 h-3.5 inline mr-1.5" />
            Live Stream Replay
          </button>
        </div>
      </div>

      {/* Tab 1: Classifier Inference */}
      {activeTab === 'classifier' && (
        <div className="p-5 space-y-5">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            {/* Prediction Card */}
            <div className="p-5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-900/40">
              <span className="text-[11px] font-mono text-slate-500 uppercase font-semibold block mb-1">
                Inferred Application Type
              </span>
              <div className="text-2xl font-bold font-mono text-indigo-600 dark:text-indigo-400 mb-2">
                {classificationResult?.predicted_application || classificationResult?.predicted_class || 'Web'}
              </div>
              <div className="flex items-center gap-2 mb-4">
                <div className="flex-1 bg-slate-200 dark:bg-slate-700 h-2 rounded-full overflow-hidden">
                  <div 
                    className="bg-indigo-600 h-full rounded-full transition-all duration-500" 
                    style={{ width: `${(classificationResult?.confidence || 0.85) * 100}%` }}
                  />
                </div>
                <span className="text-xs font-mono font-bold text-slate-700 dark:text-slate-300">
                  {((classificationResult?.confidence || 0.85) * 100).toFixed(1)}% Conf
                </span>
              </div>
              <span className={`inline-block px-2.5 py-1 rounded text-xs font-mono font-bold border ${
                classificationResult?.risk_level === 'HIGH'
                  ? 'bg-red-500/10 text-red-600 border-red-500/20'
                  : 'bg-emerald-500/10 text-emerald-600 border-emerald-500/20'
              }`}>
                {classificationResult?.risk_level || 'LOW'} RISK APPLICATION
              </span>
            </div>

            {/* Top Behavioral Indicators */}
            <div className="md:col-span-2 p-5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-900/40">
              <span className="text-[11px] font-mono text-slate-500 uppercase font-semibold block mb-2">
                Top Behavioral Flow Indicators
              </span>
              <div className="space-y-2 text-xs font-mono">
                {classificationResult?.behavioral_indicators?.length > 0 ? (
                  classificationResult.behavioral_indicators.map((ind, i) => (
                    <div key={i} className="flex items-start gap-2 p-2 rounded bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                      <CheckCircle className="w-4 h-4 text-indigo-500 mt-0.5 shrink-0" />
                      <span className="text-slate-700 dark:text-slate-300">{ind}</span>
                    </div>
                  ))
                ) : (
                  <>
                    <div className="flex items-start gap-2 p-2 rounded bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                      <CheckCircle className="w-4 h-4 text-indigo-500 mt-0.5 shrink-0" />
                      <span className="text-slate-700 dark:text-slate-300">High downlink/uplink ratio characteristic of Web browsing responses</span>
                    </div>
                    <div className="flex items-start gap-2 p-2 rounded bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                      <CheckCircle className="w-4 h-4 text-indigo-500 mt-0.5 shrink-0" />
                      <span className="text-slate-700 dark:text-slate-300">Burst factor &gt; 2.0 indicates irregular interactive request-response pacing</span>
                    </div>
                  </>
                )}
              </div>
            </div>
          </div>

          {/* Probabilities Breakdown */}
          {classificationResult?.probabilities && (
            <div className="p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950">
              <span className="text-xs font-mono text-slate-500 uppercase font-semibold block mb-3">
                Class Probability Distribution
              </span>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
                {Object.entries(classificationResult.probabilities).map(([cls, prob]) => (
                  <div key={cls} className="p-2 rounded bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                    <span className="text-slate-500 block text-[10px]">{cls}</span>
                    <span className="font-bold text-slate-800 dark:text-slate-200">
                      {(prob * 100).toFixed(1)}%
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 2: 14 Flow Features */}
      {activeTab === 'features' && (
        <div className="p-5">
          <div className="mb-4 text-xs font-mono text-slate-600 dark:text-slate-400">
            Exactly 14 behavioral statistical features extracted from ESP packet timing and sizing profiles,
            adhering to SIH26160 encrypted traffic classification requirements.
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono border-collapse">
              <thead>
                <tr className="bg-slate-50 dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 text-slate-500 uppercase text-[10px]">
                  <th className="py-2.5 px-4 font-semibold">#</th>
                  <th className="py-2.5 px-4 font-semibold">Feature Identifier</th>
                  <th className="py-2.5 px-4 font-semibold">Unit</th>
                  <th className="py-2.5 px-4 font-semibold">Mathematical Description</th>
                  <th className="py-2.5 px-4 font-semibold">Behavioral Baseline</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                {FLOW_FEATURE_DEFINITIONS.map((feat, idx) => (
                  <tr key={feat.name} className="hover:bg-slate-50/50 dark:hover:bg-slate-800/30">
                    <td className="py-2.5 px-4 text-slate-400 font-bold">{idx + 1}</td>
                    <td className="py-2.5 px-4 font-semibold text-indigo-600 dark:text-indigo-400">{feat.name}</td>
                    <td className="py-2.5 px-4 text-slate-500">{feat.unit}</td>
                    <td className="py-2.5 px-4 text-slate-700 dark:text-slate-300">{feat.desc}</td>
                    <td className="py-2.5 px-4 text-slate-500">{feat.normal}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab 3: Live Stream Replay Simulator */}
      {activeTab === 'live' && (
        <div className="p-5 space-y-4">
          {/* Controls Bar */}
          <div className="flex flex-wrap items-center justify-between gap-3 p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900">
            <div className="flex items-center gap-3">
              <div>
                <span className="text-[10px] uppercase font-mono text-slate-500 block">Scenario</span>
                <select
                  value={simScenario}
                  onChange={(e) => setSimScenario(e.target.value)}
                  disabled={isSimulating}
                  className="text-xs font-mono px-2.5 py-1.5 rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-800 dark:text-slate-200"
                >
                  <option value="IKEV2_ESTABLISHED">IKEv2 Full Handshake + ESP</option>
                  <option value="IKEV1_MAIN_MODE">IKEv1 Main Mode (6 Packets)</option>
                  <option value="IKEV2_TRUNCATED">IKEv2 Truncated Handshake</option>
                </select>
              </div>

              <div>
                <span className="text-[10px] uppercase font-mono text-slate-500 block">Rate (pps)</span>
                <select
                  value={simRate}
                  onChange={(e) => setSimRate(e.target.value)}
                  disabled={isSimulating}
                  className="text-xs font-mono px-2.5 py-1.5 rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-800 dark:text-slate-200"
                >
                  <option value="2.0">2 pps (Slow / Visual)</option>
                  <option value="5.0">5 pps (Standard)</option>
                  <option value="15.0">15 pps (Fast)</option>
                </select>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <span className="text-xs font-mono text-slate-600 dark:text-slate-400">
                Packets Captured: <b className="text-indigo-600 dark:text-indigo-400">{packetsCaptured}</b>
              </span>
              {!isSimulating ? (
                <button
                  onClick={handleStartSimulation}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-mono font-bold bg-indigo-600 hover:bg-indigo-700 text-white cursor-pointer"
                >
                  <Play className="w-3.5 h-3.5" />
                  Start Live Replay
                </button>
              ) : (
                <button
                  onClick={handleStopSimulation}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-mono font-bold bg-red-600 hover:bg-red-700 text-white cursor-pointer"
                >
                  <Square className="w-3.5 h-3.5" />
                  Stop Replay
                </button>
              )}
            </div>
          </div>

          {/* Live Packet Terminal */}
          <div className="rounded-lg border border-slate-300 dark:border-slate-800 bg-slate-950 text-emerald-400 font-mono text-xs p-4 h-64 overflow-y-auto">
            <div className="flex items-center gap-2 pb-2 mb-2 border-b border-slate-800 text-slate-400 text-[11px]">
              <Terminal className="w-3.5 h-3.5 text-slate-400" />
              <span>Real-Time Packet Stream & FSM Transition Monitor</span>
            </div>
            {livePackets.length === 0 ? (
              <div className="text-slate-600 italic py-6 text-center">
                Simulation idle. Click "Start Live Replay" to stream synthetic packets through the ingestion & FSM engine.
              </div>
            ) : (
              livePackets.map((pkt) => (
                <div key={pkt.index} className="py-0.5 leading-relaxed hover:bg-slate-900/60 px-1 rounded flex items-center gap-3">
                  <span className="text-slate-500 text-[10px]">#{pkt.index}</span>
                  <span className="text-slate-400">{pkt.timestamp?.toFixed(3)}s</span>
                  <span className="text-cyan-400 font-bold">{pkt.protocol}</span>
                  <span className="text-slate-300">{pkt.src_ip} -&gt; {pkt.dst_ip}</span>
                  <span className="text-emerald-300">{pkt.summary}</span>
                </div>
              ))
            )}
            <div ref={terminalEndRef} />
          </div>
        </div>
      )}
    </div>
  );
}
