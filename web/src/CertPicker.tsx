import { createEffect, createMemo, createSignal } from 'solid-js'
import { Cert, get, post } from './api'
import { dnsProviders } from './dnsProviders'
import DomainInput from './DomainInput'
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

const certIsCurrent = (cert: Cert) => {
  const expires = Date.parse(cert.expires_at)
  return Number.isFinite(expires) && expires > Date.now()
}

type Props = {
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
}

// Shared by HTTP hosts and mail domains. It combines selection and inline ACME
// issuance so certificate picking has one interaction model everywhere.
export default function CertPicker(props: Props) {
  const [open, setOpen] = createSignal(false)
  const [busy, setBusy] = createSignal(false)
  const [error, setError] = createSignal<string | null>(null)
  const [failedDomain, setFailedDomain] = createSignal<string | null>(null)
  const [domains, setDomains] = createSignal<string[]>([])
  const [challenge, setChallenge] = createSignal<'http' | 'dns'>('http')
  const [provider, setProvider] = createSignal('')
  const [dnsEnv, setDnsEnv] = createSignal('')

  const isolate = () => props.isolate ?? false
  const domainCerts = () => props.domainCerts ?? {}
  const matchingCerts = createMemo(() =>
    props.certs.filter(
      (cert) =>
        certIsCurrent(cert) &&
        props.defaultDomains.length > 0 &&
        props.defaultDomains.every((domain) => cert.domains.some((san) => certDomainMatches(san, domain))),
    ),
  )
  const providerEnv = createMemo(() => dnsProviders.find((item) => item.code === provider())?.env ?? [])

  createEffect(() => {
    if (!isolate() && props.value !== 0 && !matchingCerts().some((cert) => cert.id === props.value)) {
      props.onChange(0)
    }
  })

  const startIssue = () => {
    const initialDomains = props.defaultDomains.filter(Boolean)
    setDomains(initialDomains)
    setChallenge(initialDomains.some((domain) => domain.startsWith('*.')) ? 'dns' : 'http')
    setError(null)
    setFailedDomain(null)
    setOpen(true)
  }

  const issue = async () => {
    setBusy(true)
    setError(null)
    setFailedDomain(null)
    try {
      const env: Record<string, string> = {}
      for (const line of dnsEnv().split('\n')) {
        const separator = line.indexOf('=')
        if (separator > 0) env[line.slice(0, separator).trim()] = line.slice(separator + 1).trim()
      }
      const requestedDomains = isolate() ? props.defaultDomains.filter(Boolean) : domains()
      const body = {
        domains: requestedDomains,
        challenge: challenge(),
        dns_provider: provider(),
        dns_env: env,
      }

      let isolatedIDs: Record<string, number> | undefined
      if (isolate()) {
        const result = await post<{ cert_ids: Record<string, number> }>('/api/v1/certs/acme/isolated', body)
        isolatedIDs = result.cert_ids
      } else {
        await post('/api/v1/certs/acme', body)
      }

      const fresh: Cert[] = (await get('/api/v1/certs')) ?? []
      props.onCertsChanged(fresh)
      if (isolatedIDs) {
        props.onDomainCertsChange?.(isolatedIDs)
      } else {
        const created = fresh.reduce<Cert | undefined>((latest, cert) => !latest || cert.id > latest.id ? cert : latest, undefined)
        if (created) props.onChange(created.id)
      }
      setOpen(false)
    } catch (cause: any) {
      const message = cause?.message || String(cause)
      const domainMatch = message.match(/^ACME issue failed for domain "([^"]+)":\s*/)
      setFailedDomain(domainMatch?.[1] ?? null)
      setError(domainMatch ? message.slice(domainMatch[0].length) : message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div class="picker-stack">
      {props.onIsolateChange && (
        <div class="checks">
          <Check
            label="Isolate certificates (one certificate per domain)"
            checked={isolate()}
            onChange={props.onIsolateChange}
          />
        </div>
      )}

      {(!isolate() || !open()) && (
        <Row label={props.label ?? 'Certificate'}>
          <div class="picker-row">
            {isolate() ? (
              <div class="picker-summary">
                {props.defaultDomains.length ? props.defaultDomains.map((domain) => {
                  const cert = props.certs.find((item) =>
                    item.id === domainCerts()[domain] &&
                    certIsCurrent(item) &&
                    item.domains.length === 1 &&
                    item.domains[0].toLowerCase() === domain.toLowerCase(),
                  )
                  return <span class={cert ? 'picker-status ok' : 'picker-status warn'}>{domain}: {cert?.name ?? 'not issued'}</span>
                }) : <span class="hint">Add host domains before issuing certificates.</span>}
              </div>
            ) : (
              <select class="picker-control" value={props.value} onChange={(event) => props.onChange(+event.currentTarget.value)}>
                <option value={0}>{props.noneLabel ?? '— none —'}</option>
                {matchingCerts().map((cert) => (
                  <option value={cert.id}>{cert.name} ({cert.domains.join(', ')})</option>
                ))}
              </select>
            )}
            <button type="button" class="picker-action" onClick={() => open() ? setOpen(false) : startIssue()}>
              {open() ? 'Cancel' : isolate() ? '+ Issue certificates' : "+ Let's Encrypt"}
            </button>
          </div>
        </Row>
      )}

      {open() && (
        <div class="picker-panel">
          <p class="hint">HTTP-01 needs public port 80. Wildcards require DNS-01. Configure the ACME email in Settings first.</p>
          {isolate() && <p class="hint">This will issue {props.defaultDomains.length} separate single-domain certificates.</p>}
          {error() && (
            <p class="alert alert-danger">
              {failedDomain() && <>Failed domain: <strong>{failedDomain()}</strong>. The batch was rolled back. </>}
              {error()}
            </p>
          )}
          {!isolate() && (
            <Row label="Domains"><DomainInput value={domains()} onChange={setDomains} /></Row>
          )}
          <Row label="Challenge">
            <select value={challenge()} onChange={(event) => setChallenge(event.currentTarget.value as 'http' | 'dns')}>
              <option value="http">HTTP-01</option>
              <option value="dns">DNS-01</option>
            </select>
          </Row>
          {challenge() === 'dns' && (
            <>
              <Row label="DNS provider">
                <select value={provider()} onChange={(event) => setProvider(event.currentTarget.value)}>
                  <option value="">— select provider —</option>
                  {dnsProviders.map((item) => <option value={item.code}>{item.name} ({item.code})</option>)}
                </select>
              </Row>
              <Row label="Provider credentials" hint="Use KEY=value, one entry per line.">
                <textarea
                  rows={Math.max(3, providerEnv().length)}
                  value={dnsEnv()}
                  onInput={(event) => setDnsEnv(event.currentTarget.value)}
                  placeholder={providerEnv().length ? providerEnv().map((key) => `${key}=`).join('\n') : 'CLOUDFLARE_DNS_API_TOKEN=...'}
                />
              </Row>
            </>
          )}
          <div class="form-actions">
            <button type="button" class="primary" disabled={busy() || (isolate() && props.defaultDomains.length === 0)} onClick={issue}>
              {busy() ? 'Issuing…' : isolate() ? `Issue ${props.defaultDomains.length} certificates` : 'Issue & attach'}
            </button>
            <button type="button" disabled={busy()} onClick={() => setOpen(false)}>Cancel</button>
          </div>
        </div>
      )}
    </div>
  )
}
