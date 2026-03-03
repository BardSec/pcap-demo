import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import api from '../api/client'

export default function Layout({ children }) {
  const [captures, setCaptures] = useState([])

  useEffect(() => {
    api.get('/captures').then(r => setCaptures(r.data)).catch(() => {})
  }, [])

  return (
    <div className="min-h-screen bg-gray-950 flex flex-col">
      {/* Demo mode banner */}
      <div className="w-full bg-amber-500 text-gray-900 flex items-center justify-center gap-4 px-4 py-1.5 text-sm font-medium shrink-0">
        <span>Demo Mode &mdash; No login required</span>
        <span className="text-gray-700">|</span>
        <a
          href="https://github.com/BardSec/-cap-detector"
          target="_blank"
          rel="noopener noreferrer"
          className="underline hover:text-gray-700 transition font-semibold"
        >
          Get the Full Version &rarr;
        </a>
      </div>

      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar */}
        <aside className="w-64 bg-gray-900 border-r border-gray-800 flex flex-col shrink-0">
          {/* Brand */}
          <div className="p-5 border-b border-gray-800">
            <Link to="/" className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-lg bg-brand-600 flex items-center justify-center">
                <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                    d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
                </svg>
              </div>
              <div>
                <div className="text-sm font-bold text-white leading-tight">PCAP Bloodhound</div>
                <div className="text-xs text-gray-500">Network Threat Hunter</div>
              </div>
            </Link>
          </div>

          {/* Sample captures button */}
          <div className="p-4">
            <Link
              to="/"
              className="flex items-center justify-center gap-2 w-full bg-brand-600 hover:bg-brand-700 text-white text-sm font-medium py-2.5 px-4 rounded-lg transition"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 10h16M4 14h16M4 18h16" />
              </svg>
              Sample Captures
            </Link>
          </div>

          {/* Capture list */}
          <div className="flex-1 overflow-y-auto px-4">
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">Samples</p>
            <div className="space-y-1">
              {captures.map(c => (
                <Link
                  key={c.id}
                  to={`/capture/${c.id}`}
                  className="block rounded-lg px-3 py-2 hover:bg-gray-800 transition group"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-sm text-gray-300 truncate group-hover:text-white">{c.filename}</span>
                    <StatusDot status={c.status} />
                  </div>
                  <p className="text-xs text-gray-600 mt-0.5">
                    {c.packet_count ? `${c.packet_count.toLocaleString()} pkts` : c.status}
                  </p>
                </Link>
              ))}
              {captures.length === 0 && (
                <p className="text-xs text-gray-600 px-3 py-2">Loading samples…</p>
              )}
            </div>
          </div>

          {/* Demo mode footer */}
          <div className="p-4 border-t border-gray-800">
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-amber-400" />
              <span className="text-xs text-gray-400">Demo Mode</span>
            </div>
            <p className="text-xs text-gray-600 mt-1 leading-relaxed">
              Upload disabled.{' '}
              <a
                href="https://github.com/BardSec/-cap-detector"
                target="_blank"
                rel="noopener noreferrer"
                className="text-brand-400 hover:underline"
              >
                Get the full app
              </a>{' '}
              to analyze your own PCAPs.
            </p>
          </div>
        </aside>

        {/* Main content */}
        <main className="flex-1 overflow-y-auto">
          {children}
        </main>
      </div>
    </div>
  )
}

function StatusDot({ status }) {
  const colors = {
    complete: 'bg-green-500',
    processing: 'bg-yellow-500 animate-pulse',
    pending: 'bg-yellow-500 animate-pulse',
    failed: 'bg-red-500',
  }
  return <span className={`w-2 h-2 rounded-full shrink-0 ${colors[status] || 'bg-gray-600'}`} />
}
