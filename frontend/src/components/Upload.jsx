import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import api from '../api/client'

const SAMPLE_DESCRIPTIONS = {
  'cobalt-strike-beacon.pcap':    'Cobalt Strike-style C2 implant pinging home every 60 s with captured NTLMv2 hashes.',
  'dns-exfiltration-iodine.pcap': 'iodine DNS-tunnel exfiltrating ~300 KB of data via high-entropy TXT queries.',
  'cleartext-credentials.pcap':   'Five FTP accounts and two HTTP Basic Auth logins transmitted in the clear.',
  'lateral-movement-smb.pcap':    'Six NTLMv2 hashes collected during SMB lateral movement + a Meterpreter C2 channel.',
  'network-health-audit.pcap':    'Clean-ish traffic with DNS timeouts, stale NXDOMAIN lookups, and a deprecated TLS 1.0 session.',
}

const SEVERITY_TAG = {
  'cobalt-strike-beacon.pcap':    { label: 'CRITICAL', cls: 'bg-red-900/40 text-red-300 border-red-700/50' },
  'dns-exfiltration-iodine.pcap': { label: 'CRITICAL', cls: 'bg-red-900/40 text-red-300 border-red-700/50' },
  'cleartext-credentials.pcap':   { label: 'HIGH',     cls: 'bg-orange-900/40 text-orange-300 border-orange-700/50' },
  'lateral-movement-smb.pcap':    { label: 'CRITICAL', cls: 'bg-red-900/40 text-red-300 border-red-700/50' },
  'network-health-audit.pcap':    { label: 'INFO',     cls: 'bg-blue-900/40 text-blue-300 border-blue-700/50' },
}

export default function Upload() {
  const [captures, setCaptures] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.get('/captures').then(r => {
      setCaptures(r.data)
      setLoading(false)
    }).catch(() => setLoading(false))
  }, [])

  return (
    <div className="min-h-full flex flex-col items-center justify-center p-8">
      <div className="w-full max-w-2xl">
        <h1 className="text-2xl font-bold text-white mb-2">Sample PCAP Captures</h1>
        <p className="text-gray-400 text-sm mb-8">
          Select a capture below to explore the automated threat-analysis results.
          Upload is disabled in demo mode —{' '}
          <a
            href="https://github.com/BardSec/-cap-detector"
            target="_blank"
            rel="noopener noreferrer"
            className="text-brand-400 hover:underline"
          >
            get the full version
          </a>
          {' '}to analyze your own files.
        </p>

        {loading && (
          <div className="flex items-center justify-center py-16">
            <div className="w-8 h-8 border-4 border-brand-500 border-t-transparent rounded-full animate-spin" />
          </div>
        )}

        <div className="space-y-3">
          {captures.map(c => {
            const tag = SEVERITY_TAG[c.filename] || { label: 'INFO', cls: 'bg-gray-800 text-gray-400 border-gray-700' }
            const desc = SAMPLE_DESCRIPTIONS[c.filename] || 'Pre-analyzed PCAP capture.'
            return (
              <Link
                key={c.id}
                to={`/capture/${c.id}`}
                className="block bg-gray-900 border border-gray-800 rounded-xl p-5 hover:border-gray-600 hover:bg-gray-900/80 transition group"
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`text-xs font-bold px-2 py-0.5 rounded border ${tag.cls}`}>
                        {tag.label}
                      </span>
                      <h3 className="text-sm font-semibold text-white truncate group-hover:text-brand-400 transition">
                        {c.filename}
                      </h3>
                    </div>
                    <p className="text-xs text-gray-400 leading-relaxed">{desc}</p>
                    <p className="text-xs text-gray-600 mt-2">
                      {c.packet_count?.toLocaleString()} packets &middot; {(c.file_size / 1024 / 1024).toFixed(1)} MB
                    </p>
                  </div>
                  <svg className="w-5 h-5 text-gray-600 group-hover:text-brand-400 transition shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                  </svg>
                </div>
              </Link>
            )
          })}
        </div>

        {/* Detection capabilities */}
        <div className="mt-10 grid grid-cols-1 sm:grid-cols-2 gap-4">
          {DETECTIONS.map((d) => (
            <div key={d.title} className="bg-gray-900 border border-gray-800 rounded-xl p-4">
              <div className="flex items-center gap-3 mb-2">
                <span className="text-2xl">{d.icon}</span>
                <h3 className="text-sm font-semibold text-white">{d.title}</h3>
              </div>
              <p className="text-xs text-gray-400 leading-relaxed">{d.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

const DETECTIONS = [
  {
    icon: '📡',
    title: 'C2 Beaconing Detection',
    desc: 'Calculates the coefficient of variation on inter-arrival times. CV < 0.15 flags implant heartbeats from tools like Cobalt Strike and Sliver.',
  },
  {
    icon: '🕳️',
    title: 'DNS Tunneling Detection',
    desc: 'Entropy-scores every DNS query. Scores above 3.8 bits or subdomains longer than 50 chars indicate iodine/dnscat2 exfiltration.',
  },
  {
    icon: '🔑',
    title: 'NTLM Hash Extraction',
    desc: 'Parses NTLMSSP exchanges to extract server challenges and NTLMv2 hashes formatted for Hashcat (mode 5600).',
  },
  {
    icon: '🚨',
    title: 'Cleartext Credentials',
    desc: 'Detects HTTP Basic Auth, FTP USER/PASS, SMTP AUTH LOGIN, and HTTP form POSTs with password fields.',
  },
  {
    icon: '📤',
    title: 'Exfiltration Profiling',
    desc: 'Flags outbound flows exceeding 1 MB with >5:1 send/receive asymmetry with bandwidth and duration stats.',
  },
]
