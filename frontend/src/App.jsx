import { useEffect, useState } from 'react'
import { Routes, Route, Navigate, useSearchParams } from 'react-router-dom'
import Layout from './components/Layout'
import Upload from './components/Upload'
import Dashboard from './components/Dashboard'
import api from './api/client'

export default function App() {
  const [token, setToken] = useState(() => localStorage.getItem('token'))
  const [searchParams, setSearchParams] = useSearchParams()

  // OAuth redirect lands here with ?token=...
  useEffect(() => {
    const t = searchParams.get('token')
    if (t) {
      localStorage.setItem('token', t)
      setToken(t)
      setSearchParams({})
    }
  }, [searchParams, setSearchParams])

  // Demo mode: auto-fetch a demo token if we have none
  useEffect(() => {
    if (token) return
    api.get('/demo-token').then(r => {
      if (r.data.token) {
        localStorage.setItem('token', r.data.token)
        setToken(r.data.token)
      }
    }).catch(() => {})
  }, [token])

  const logout = () => {
    localStorage.removeItem('token')
    setToken(null)
  }

  if (!token) return null

  return (
    <Layout onLogout={logout}>
      <Routes>
        <Route path="/" element={<Upload />} />
        <Route path="/capture/:id" element={<Dashboard />} />
        <Route path="*" element={<Navigate to="/" />} />
      </Routes>
    </Layout>
  )
}
