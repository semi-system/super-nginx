import { useEffect, useState } from 'react'
import { get, post, Cert } from './api'
import { Check, Row } from './ui'

function certDomainMatches(san: string, domain: string) {
  san = san.trim().toLowerCase()
  domain = domain.trim().toLowerCase()
  if (san === domain) return true
  if (!san.startsWith('*.') || domain.startsWith('*.')) return false
  const suffix = san.slice(1)
  if (!domain.endsWith(suffix)) return false
  const label = domain.slice(0, -suffix.length)
  return label.length > 0 && !label.includes('.')
}

function certCoversDomain(cert: Cert, domain: string) {
  return cert.domains.some((san) => certDomainMatches(san, domain))
}

function certIsCurrent(cert: Cert) {
  const expires = Date.parse(cert.expires_at)
  return Number.isFinite(expires) && expires > Date.now()
}

// Certificate selector with inline Let's Encrypt issuance, so hosts and mail
// domains don't have to bounce to the Certs tab. Reused in Hosts + Mail.
export default function CertPicker({
  value,
  certs,
  defaultDomains,
  label = 'Certificate',
  noneLabel = '— none —',
  onChange,
  onCertsChanged,
  isolate = false,
  domainCerts = {},
  onIsolateChange,
  onDomainCertsChange,
}: {
  value: number
  certs: Cert[]
  defaultDomains: string[]
  label?: string
  noneLabel?: string
  onChange: (id: number) => void
  onCertsChanged: (certs: Cert[]) => void
  isolate?: boolean
  domainCerts?: Record<string, number>
  onIsolateChange?: (isolate: boolean) => void
  onDomainCertsChange?: (certs: Record<string, number>) => void
}) {
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [failedDomain, setFailedDomain] = useState<string | null>(null)
  const [domains, setDomains] = useState('')
  const [challenge, setChallenge] = useState<'http' | 'dns'>('http')
  const [provider, setProvider] = useState('')
  const [dnsEnv, setDnsEnv] = useState('')

  const matchingCerts = certs.filter(
    (cert) =>
      certIsCurrent(cert) &&
      defaultDomains.length > 0 &&
      defaultDomains.every((domain) => certCoversDomain(cert, domain)),
  )

  useEffect(() => {
    if (!isolate && value !== 0 && !matchingCerts.some((cert) => cert.id === value)) {
      onChange(0)
    }
  }, [isolate, value, certs, defaultDomains, onChange])

  const startIssue = () => {
    const d = defaultDomains.filter(Boolean)
    setDomains(d.join(' '))
    setChallenge(d.some((x) => x.startsWith('*.')) ? 'dns' : 'http')
    setErr(null)
    setFailedDomain(null)
    setOpen(true)
  }

  const issue = async () => {
    setBusy(true)
    setErr(null)
    setFailedDomain(null)
    try {
      const env: Record<string, string> = {}
      for (const line of dnsEnv.split('\n')) {
        const i = line.indexOf('=')
        if (i > 0) env[line.slice(0, i).trim()] = line.slice(i + 1).trim()
      }
      const requestedDomains = isolate
        ? defaultDomains.filter(Boolean)
        : domains.split(/[\s,]+/).filter(Boolean)
      const body = {
        domains: requestedDomains,
        challenge,
        dns_provider: provider,
        dns_env: env,
      }
      let isolatedIDs: Record<string, number> | null = null
      if (isolate) {
        const result = await post<{ cert_ids: Record<string, number> }>('/api/v1/certs/acme/isolated', body)
        isolatedIDs = result.cert_ids
      } else {
        await post('/api/v1/certs/acme', body)
      }
      const fresh: Cert[] = (await get('/api/v1/certs')) ?? []
      onCertsChanged(fresh)
      if (isolatedIDs) {
        onDomainCertsChange?.(isolatedIDs)
      } else {
        // synchronous single-user issuance: the cert we just made has the max id
        // ponytail: match by highest id instead of threading the id back through the API
        const created = fresh.reduce((a, b) => (b.id > a.id ? b : a), fresh[0])
        if (created) onChange(created.id)
      }
      setOpen(false)
    } catch (e: any) {
      const message = e.message || String(e)
      const domainMatch = message.match(/^ACME issue failed for domain "([^"]+)":\s*/)
      setFailedDomain(domainMatch?.[1] ?? null)
      setErr(domainMatch ? message.slice(domainMatch[0].length) : message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      {onIsolateChange && (
        <div className="checks">
          <Check
            label="Isolate certificates (issue one certificate per domain so sibling names are not exposed in SANs)"
            checked={isolate}
            onChange={onIsolateChange}
          />
        </div>
      )}
      {(!isolate || !open) && (
        <Row label={label}>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            {isolate ? (
              <div style={{ flex: 1 }}>
                {defaultDomains.length ? (
                  defaultDomains.map((domain) => {
                    const cert = certs.find(
                      (c) =>
                        c.id === domainCerts[domain] &&
                        certIsCurrent(c) &&
                        c.domains.length === 1 &&
                        c.domains[0].toLowerCase() === domain.toLowerCase(),
                    )
                    return (
                      <div key={domain} className="hint">
                        {domain}: {cert ? cert.name : 'certificate not issued'}
                      </div>
                    )
                  })
                ) : (
                  <span className="hint">Add host domains before issuing certificates.</span>
                )}
              </div>
            ) : (
              <select style={{ flex: 1 }} value={value} onChange={(e) => onChange(+e.target.value)}>
                <option value={0}>{noneLabel}</option>
                {matchingCerts.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name} ({c.domains.join(', ')})
                  </option>
                ))}
              </select>
            )}
            <button type="button" onClick={() => (open ? setOpen(false) : startIssue())}>
              {open ? 'Cancel' : isolate ? '＋ Issue isolated certs' : "＋ Let's Encrypt"}
            </button>
          </div>
        </Row>
      )}

      {open && (
        <div className="editor" style={{ margin: '4px 0 12px' }}>
          <p className="hint">
            HTTP challenge needs port 80 → 8080 reachable from the internet. Wildcards need the DNS
            challenge. Set the ACME email in Settings first.
          </p>
          {isolate && <p className="hint">Issuing {defaultDomains.length} separate single-domain certificates.</p>}
          {err && (
            <p className="error">
              {failedDomain && (
                <>
                  Failed domain: <strong>{failedDomain}</strong>. The isolated certificate batch was rolled back.{' '}
                </>
              )}
              {err}
            </p>
          )}
          {!isolate && (
            <Row label="Domains (space separated)">
              <input value={domains} onChange={(e) => setDomains(e.target.value)} />
            </Row>
          )}
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
            <button type="button" disabled={busy || (isolate && defaultDomains.length === 0)} onClick={issue}>
              {busy ? 'Issuing…' : isolate ? `Issue ${defaultDomains.length} certificates` : 'Issue & attach'}
            </button>
            {isolate && (
              <button type="button" disabled={busy} onClick={() => setOpen(false)}>
                Cancel
              </button>
            )}
          </div>
        </div>
      )}
    </>
  )
}
