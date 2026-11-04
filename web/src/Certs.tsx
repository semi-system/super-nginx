import { useEffect, useMemo, useState } from 'react'
import { get, post, del, Cert } from './api'
import { Err, Row, Modal, Pagination, useAsync, usePaged } from './ui'
import { dnsProviders } from './dnsProviders'

function certIsExpired(cert: Cert) {
  const expires = Date.parse(cert.expires_at)
  return Number.isFinite(expires) && expires <= Date.now()
}

function certIsExpiring(cert: Cert) {
  const expires = Date.parse(cert.expires_at)
  const thirtyDays = 30 * 24 * 60 * 60 * 1000
  return Number.isFinite(expires) && expires > Date.now() && expires <= Date.now() + thirtyDays
}

export default function Certs() {
  const [certs, setCerts] = useState<Cert[]>([])
  const [mode, setMode] = useState<'none' | 'custom' | 'acme'>('none')
  const [notice, setNotice] = useState('')
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('all')
  const [challengeFilter, setChallengeFilter] = useState('all')
  const [statusFilter, setStatusFilter] = useState('all')
  const { error, busy, run, setError } = useAsync()
  const filteredCerts = useMemo(() => {
    const query = search.trim().toLowerCase()
    return certs.filter((cert) => {
      const textMatches = [cert.name, cert.type, cert.challenge ?? '', cert.domains.join(' '), cert.last_error ?? 'ok']
        .join(' ')
        .toLowerCase()
        .includes(query)
      if (!textMatches || (typeFilter !== 'all' && cert.type !== typeFilter)) return false
      if (challengeFilter !== 'all' && cert.challenge !== challengeFilter) return false
      if (statusFilter === 'valid' && (cert.last_error || certIsExpired(cert) || certIsExpiring(cert))) return false
      if (statusFilter === 'expiring' && (cert.last_error || !certIsExpiring(cert))) return false
      if (statusFilter === 'expired' && !certIsExpired(cert)) return false
      if (statusFilter === 'error' && !cert.last_error) return false
      return true
    })
  }, [certs, search, typeFilter, challengeFilter, statusFilter])
  const paged = usePaged(filteredCerts)

  // custom form
  const [certPEM, setCertPEM] = useState('')
  const [keyPEM, setKeyPEM] = useState('')
  // acme form
  const [domains, setDomains] = useState('')
  const [challenge, setChallenge] = useState<'http' | 'dns'>('http')
  const [provider, setProvider] = useState('')
  const [dnsEnv, setDnsEnv] = useState('')

  const providerEnv = dnsProviders.find((p) => p.code === provider)?.env ?? []

  const reload = async () => setCerts((await get('/api/v1/certs')) ?? [])
  useEffect(() => {
    run(reload)
  }, [])

  const submitCustom = () =>
    run(async () => {
      await post('/api/v1/certs/custom', { cert: certPEM, key: keyPEM })
      setMode('none')
      setCertPEM('')
      setKeyPEM('')
      await reload()
    })

  const submitACME = () =>
    run(async () => {
      const env: Record<string, string> = {}
      for (const line of dnsEnv.split('\n')) {
        const i = line.indexOf('=')
        if (i > 0) env[line.slice(0, i).trim()] = line.slice(i + 1).trim()
      }
      await post('/api/v1/certs/acme', {
        domains: domains.split(/[\s,]+/).filter(Boolean),
        challenge,
        dns_provider: provider,
        dns_env: env,
      })
      setMode('none')
      setDomains('')
      await reload()
    })

  const renew = (id: number) =>
    run(async () => {
      await post(`/api/v1/certs/${id}/renew`)
      await reload()
    })

  const remove = (id: number) =>
    run(async () => {
      if (!confirm('Delete this certificate?')) return
      await del(`/api/v1/certs/${id}`)
      await reload()
    })

  const cleanupCandidateCount = certs.filter((cert) => certIsExpired(cert) || cert.type === 'acme').length

  const cleanupCerts = () =>
    run(async () => {
      if (
        !confirm(
          `Delete unused expired certificates and unused Let's Encrypt certificates? (${cleanupCandidateCount} candidates)`,
        )
      )
        return
      const result = await post<{
        removed: { id: number; name: string }[]
        skipped: { id: number; name: string; reason: string }[]
      }>('/api/v1/certs/cleanup')
      const skipped = result.skipped.length
        ? ` Skipped ${result.skipped.length}: ${result.skipped.map((c) => `${c.name} (${c.reason})`).join(', ')}.`
        : ''
      setNotice(`Removed ${result.removed.length} unused or expired certificate(s).${skipped}`)
      await reload()
    })

  return (
    <section>
      <div className="bar">
        <h2>Certificates</h2>
        <button onClick={() => { setMode('acme'); setError(null) }}>+ Let's Encrypt</button>
        <button onClick={() => { setMode('custom'); setError(null) }}>+ Upload custom</button>
        <button type="button" disabled={busy || cleanupCandidateCount === 0} onClick={cleanupCerts}>
          Clean expired / unused ACME{cleanupCandidateCount > 0 ? ` (${cleanupCandidateCount})` : ''}
        </button>
      </div>
      <div className="filter-bar" aria-label="Certificate filters">
        <input
          type="search"
          aria-label="Search certificates"
          placeholder="Name or SAN..."
          value={search}
          onChange={(e) => {
            setSearch(e.target.value)
            paged.setPage(1)
          }}
        />
        <select
          aria-label="Filter certificates by type"
          value={typeFilter}
          onChange={(e) => {
            setTypeFilter(e.target.value)
            paged.setPage(1)
          }}
        >
          <option value="all">All types</option>
          <option value="acme">Let's Encrypt / ACME</option>
          <option value="custom">Custom</option>
        </select>
        <select
          aria-label="Filter certificates by challenge"
          value={challengeFilter}
          onChange={(e) => {
            setChallengeFilter(e.target.value)
            paged.setPage(1)
          }}
        >
          <option value="all">All challenges</option>
          <option value="http">HTTP-01</option>
          <option value="dns">DNS-01</option>
        </select>
        <select
          aria-label="Filter certificates by status"
          value={statusFilter}
          onChange={(e) => {
            setStatusFilter(e.target.value)
            paged.setPage(1)
          }}
        >
          <option value="all">All statuses</option>
          <option value="valid">Valid over 30 days</option>
          <option value="expiring">Expiring within 30 days</option>
          <option value="expired">Expired</option>
          <option value="error">Has error</option>
        </select>
        <button
          type="button"
          disabled={!search && typeFilter === 'all' && challengeFilter === 'all' && statusFilter === 'all'}
          onClick={() => {
            setSearch('')
            setTypeFilter('all')
            setChallengeFilter('all')
            setStatusFilter('all')
            paged.setPage(1)
          }}
        >
          Clear
        </button>
      </div>
      <Err msg={error} />
      {notice && <p className="ok">{notice}</p>}
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Domains</th>
            <th>Expires</th>
            <th>Status</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {paged.rows.map((c) => (
            <tr key={c.id}>
              <td>{c.name}</td>
              <td>{c.type === 'acme' ? `acme/${c.challenge}` : 'custom'}</td>
              <td>{c.domains.join(', ')}</td>
              <td>{c.expires_at ? new Date(c.expires_at).toLocaleDateString() : '—'}</td>
              <td className={certIsExpired(c) || c.last_error ? 'error' : ''}>
                {certIsExpired(c) ? 'expired' : c.last_error || 'ok'}
              </td>
              <td>
                {c.type === 'acme' && (
                  <button disabled={busy} onClick={() => renew(c.id)}>
                    Renew
                  </button>
                )}{' '}
                <button type="button" onClick={() => (window.location.href = `/api/v1/certs/${c.id}/download`)}>
                  Download
                </button>{' '}
                <button onClick={() => remove(c.id)}>Delete</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <Pagination {...paged} />

      {mode === 'custom' && (
        <Modal onClose={() => setMode('none')}>
        <form className="editor" onSubmit={(e) => { e.preventDefault(); submitCustom() }}>
          <h3>Upload certificate</h3>
          <Row label="Certificate (fullchain PEM)">
            <textarea rows={6} value={certPEM} onChange={(e) => setCertPEM(e.target.value)} />
          </Row>
          <Row label="Private key (PEM)">
            <textarea rows={6} value={keyPEM} onChange={(e) => setKeyPEM(e.target.value)} />
          </Row>
          <div className="bar">
            <button type="submit" disabled={busy}>Upload</button>
            <button type="button" onClick={() => setMode('none')}>Cancel</button>
          </div>
        </form>
        </Modal>
      )}

      {mode === 'acme' && (
        <Modal onClose={() => setMode('none')}>
        <form className="editor" onSubmit={(e) => { e.preventDefault(); submitACME() }}>
          <h3>Let's Encrypt certificate</h3>
          <p className="hint">
            HTTP challenge needs port 80 → 8080 reachable from the internet. Wildcards need the DNS
            challenge. Set the ACME email in Settings first.
          </p>
          <Row label="Domains (space separated)">
            <input value={domains} onChange={(e) => setDomains(e.target.value)} placeholder="example.com *.example.com" />
          </Row>
          <Row label="Challenge">
            <select value={challenge} onChange={(e) => setChallenge(e.target.value as 'http' | 'dns')}>
              <option value="http">HTTP-01</option>
              <option value="dns">DNS-01</option>
            </select>
          </Row>
          {challenge === 'dns' && (
            <>
              <Row label="DNS provider">
                <select value={provider} onChange={(e) => setProvider(e.target.value)}>
                  <option value="">— select provider —</option>
                  {dnsProviders.map((p) => (
                    <option key={p.code} value={p.code}>
                      {p.name} ({p.code})
                    </option>
                  ))}
                </select>
              </Row>
              <Row label="Provider credentials (KEY=value per line — not every key is required, see lego docs)">
                <textarea
                  rows={Math.max(3, providerEnv.length)}
                  value={dnsEnv}
                  onChange={(e) => setDnsEnv(e.target.value)}
                  placeholder={
                    providerEnv.length ? providerEnv.map((k) => k + '=').join('\n') : 'CLOUDFLARE_DNS_API_TOKEN=...'
                  }
                />
              </Row>
            </>
          )}
          <div className="bar">
            <button type="submit" disabled={busy}>
              {busy ? 'Issuing…' : 'Issue certificate'}
            </button>
            <button type="button" onClick={() => setMode('none')}>Cancel</button>
          </div>
        </form>
        </Modal>
      )}
    </section>
  )
}
