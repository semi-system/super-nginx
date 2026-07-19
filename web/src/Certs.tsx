import { useEffect, useState } from 'react'
import { get, post, del, Cert } from './api'
import { Err, Row, useAsync } from './ui'

export default function Certs() {
  const [certs, setCerts] = useState<Cert[]>([])
  const [mode, setMode] = useState<'none' | 'custom' | 'acme'>('none')
  const { error, busy, run, setError } = useAsync()

  // custom form
  const [name, setName] = useState('')
  const [certPEM, setCertPEM] = useState('')
  const [keyPEM, setKeyPEM] = useState('')
  // acme form
  const [domains, setDomains] = useState('')
  const [challenge, setChallenge] = useState<'http' | 'dns'>('http')
  const [provider, setProvider] = useState('')
  const [dnsEnv, setDnsEnv] = useState('')

  const reload = async () => setCerts((await get('/api/v1/certs')) ?? [])
  useEffect(() => {
    run(reload)
  }, [])

  const submitCustom = () =>
    run(async () => {
      await post('/api/v1/certs/custom', { name, cert: certPEM, key: keyPEM })
      setMode('none')
      setName('')
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
        name,
        domains: domains.split(/[\s,]+/).filter(Boolean),
        challenge,
        dns_provider: provider,
        dns_env: env,
      })
      setMode('none')
      setName('')
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

  return (
    <section>
      <div className="bar">
        <h2>Certificates</h2>
        <button onClick={() => { setMode('acme'); setError(null) }}>+ Let's Encrypt</button>
        <button onClick={() => { setMode('custom'); setError(null) }}>+ Upload custom</button>
      </div>
      <Err msg={error} />
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
          {certs.map((c) => (
            <tr key={c.id}>
              <td>{c.name}</td>
              <td>{c.type === 'acme' ? `acme/${c.challenge}` : 'custom'}</td>
              <td>{c.domains.join(', ')}</td>
              <td>{c.expires_at ? new Date(c.expires_at).toLocaleDateString() : '—'}</td>
              <td className={c.last_error ? 'error' : ''}>{c.last_error || 'ok'}</td>
              <td>
                {c.type === 'acme' && (
                  <button disabled={busy} onClick={() => renew(c.id)}>
                    Renew
                  </button>
                )}{' '}
                <button onClick={() => remove(c.id)}>Delete</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {mode === 'custom' && (
        <form className="editor" onSubmit={(e) => { e.preventDefault(); submitCustom() }}>
          <h3>Upload certificate</h3>
          <Row label="Name">
            <input value={name} onChange={(e) => setName(e.target.value)} />
          </Row>
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
      )}

      {mode === 'acme' && (
        <form className="editor" onSubmit={(e) => { e.preventDefault(); submitACME() }}>
          <h3>Let's Encrypt certificate</h3>
          <p className="hint">
            HTTP challenge needs port 80 → 8080 reachable from the internet. Wildcards need the DNS
            challenge. Set the ACME email in Settings first.
          </p>
          <Row label="Name">
            <input value={name} onChange={(e) => setName(e.target.value)} />
          </Row>
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
              <Row label="DNS provider (lego name, e.g. cloudflare)">
                <input value={provider} onChange={(e) => setProvider(e.target.value)} />
              </Row>
              <Row label="Provider credentials (KEY=value per line)">
                <textarea
                  rows={3}
                  value={dnsEnv}
                  onChange={(e) => setDnsEnv(e.target.value)}
                  placeholder="CLOUDFLARE_DNS_API_TOKEN=..."
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
      )}
    </section>
  )
}
