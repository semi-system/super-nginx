import { createSignal, onMount } from 'solid-js'
import { get, post, put, del, MailListener, MailDomain, Cert } from './api'
import { Err, Row, Check, Modal, Pagination, useAsync, usePaged } from './ui'
import CertPicker from './CertPicker'

const emptyListener: MailListener = {
  id: 0,
  label: 'smtp',
  port: 2465,
  mode: 'terminate',
  default_backend: '',
  proxy_ssl: false,
  enabled: true,
}

const knownProtocols = ['smtp', 'imap', 'pop3']

// [label, container port, backend port]: terminate + re-encrypt to the backend TLS ports
const presets = [['smtp', 2465, 465], ['imap', 2993, 993], ['pop3', 2995, 995]] as const

const emptyDomain: MailDomain = { id: 0, domain: '', cert_id: 0 }

export default function Mail() {
  const [listeners, setListeners] = createSignal<MailListener[]>([])
  const [domains, setDomains] = createSignal<MailDomain[]>([])
  const [certs, setCerts] = createSignal<Cert[]>([])
  const [editL, setEditL] = createSignal<MailListener | null>(null)
  const [editD, setEditD] = createSignal<MailDomain | null>(null)
  const { error, busy, run } = useAsync()
  const domainPaged = usePaged(domains)
  const listenerPaged = usePaged(listeners)

  const reload = async () => {
    setListeners((await get('/api/v1/mail/listeners')) ?? [])
    setDomains((await get('/api/v1/mail/domains')) ?? [])
    setCerts((await get('/api/v1/certs')) ?? [])
  }
  onMount(() => {
    run(reload)
  })

  const saveL = () =>
    run(async () => {
      const current = editL()
      if (!current) return
      if (current.id === 0) await post('/api/v1/mail/listeners', { ...current, id: undefined })
      else await put(`/api/v1/mail/listeners/${current.id}`, current)
      setEditL(null)
      await reload()
    })

  const saveD = () =>
    run(async () => {
      const current = editD()
      if (!current) return
      if (current.id === 0) await post('/api/v1/mail/domains', { ...current, id: undefined })
      else await put(`/api/v1/mail/domains/${current.id}`, current)
      setEditD(null)
      await reload()
    })

  const addPresets = () =>
    run(async () => {
      const host = prompt('Mail server host (e.g. 10.0.0.5)')?.trim()
      if (!host) return
      for (const [label, port, backendPort] of presets) {
        await post('/api/v1/mail/listeners', { ...emptyListener, id: undefined, label, port, default_backend: `${host}:${backendPort}`, mode: 'terminate', proxy_ssl: true })
      }
      await reload()
    })

  const removeL = (id: number) =>
    run(async () => {
      if (!confirm('Delete listener?')) return
      await del(`/api/v1/mail/listeners/${id}`)
      await reload()
    })

  const removeD = (id: number) =>
    run(async () => {
      if (!confirm('Delete mail domain?')) return
      await del(`/api/v1/mail/domains/${id}`)
      await reload()
    })

  return (
    <section>
      <h2>Mail proxy</h2>
      <p class="hint">
        Pure TCP/TLS proxy (nginx stream) — authentication stays on the backend mail server.
        Terminate mode ends TLS here with SNI per-domain certificates (implicit TLS: SMTPS 465,
        IMAPS 993, POP3S 995) and forwards plaintext, so the backend is its plain port (IMAP 143,
        POP3 110, SMTP 25). Tick "re-encrypt" to instead forward TLS to the backend's TLS port
        (993/995/465). Plain/STARTTLS-only ports use passthrough: the backend holds the cert.
        Domains only pick the certificate by SNI and apply to every listener; each listener
        forwards all of them to its own backend.
      </p>
      <Err msg={error()} />

      <div class="bar">
        <h3>Domains</h3>
        <button onClick={() => setEditD({ ...emptyDomain })}>+ Add domain</button>
      </div>
      <table>
        <thead>
          <tr>
            <th>Domain (SNI)</th>
            <th>Certificate</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {domainPaged.rows().map((d) => (
            <tr>
              <td>{d.domain}</td>
              <td>{certs().find((c) => c.id === d.cert_id)?.name || '—'}</td>
              <td>
                <button onClick={() => setEditD({ ...d })}>Edit</button>{' '}
                <button onClick={() => removeD(d.id)}>Delete</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <Pagination {...domainPaged} />

      {editD() && (
        <Modal onClose={() => setEditD(null)}>
        <form class="editor" onSubmit={(e) => { e.preventDefault(); saveD() }}>
          <h3>{editD()!.id ? 'Edit domain' : 'New mail domain'}</h3>
          <Row label="Domain (as sent in SNI, e.g. mail.example.com)">
            <input value={editD()!.domain} onInput={(e) => setEditD({ ...editD()!, domain: e.currentTarget.value })} />
          </Row>
          <CertPicker
            label="Certificate (served on every terminate listener — can be the same cert an HTTPS host uses)"
            value={editD()!.cert_id}
            certs={certs()}
            defaultDomains={editD()!.domain ? [editD()!.domain] : []}
            onChange={(id) => setEditD({ ...editD()!, cert_id: id })}
            onCertsChanged={setCerts}
          />
          <div class="bar">
            <button type="submit" disabled={busy()}>Save & apply</button>
            <button type="button" onClick={() => setEditD(null)}>Cancel</button>
          </div>
        </form>
        </Modal>
      )}

      <div class="bar">
        <h3>Listeners</h3>
        <button onClick={() => setEditL({ ...emptyListener })}>+ Add listener</button>
        <button onClick={addPresets} disabled={busy()} title="Creates 2465→host:465, 2993→host:993, 2995→host:995 (terminate, re-encrypt). Add a domain with a certificate first.">
          + SMTPS / IMAPS / POP3S
        </button>
      </div>
      <table>
        <thead>
          <tr>
            <th>Protocol</th>
            <th>Port</th>
            <th>Mode</th>
            <th>Backend</th>
            <th>On</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {listenerPaged.rows().map((l) => (
            <tr>
              <td>{l.label}</td>
              <td>{l.port}</td>
              <td>{l.mode}{l.mode === 'terminate' && l.proxy_ssl ? ' (re-encrypt)' : ''}</td>
              <td>{l.default_backend || '—'}</td>
              <td>{l.enabled ? '✓' : '✗'}</td>
              <td>
                <button onClick={() => setEditL({ ...l })}>Edit</button>{' '}
                <button onClick={() => removeL(l.id)}>Delete</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <Pagination {...listenerPaged} />

      {editL() && (
        <Modal onClose={() => setEditL(null)}>
        <form class="editor" onSubmit={(e) => { e.preventDefault(); saveL() }}>
          <h3>{editL()!.id ? 'Edit listener' : 'New listener'}</h3>
          <Row label="Protocol (display only)">
            <select
              value={knownProtocols.includes(editL()!.label) ? editL()!.label : 'other'}
              onChange={(e) => setEditL({ ...editL()!, label: e.currentTarget.value === 'other' ? '' : e.currentTarget.value })}
            >
              <option value="smtp">smtp</option>
              <option value="imap">imap</option>
              <option value="pop3">pop3</option>
              <option value="other">other…</option>
            </select>
          </Row>
          {!knownProtocols.includes(editL()!.label) && (
            <Row label="Custom protocol name">
              <input value={editL()!.label} onInput={(e) => setEditL({ ...editL()!, label: e.currentTarget.value })} />
            </Row>
          )}
          <Row label="Container port (>1024; map from host, e.g. 465 → 2465)">
            <input type="number" value={editL()!.port} onInput={(e) => setEditL({ ...editL()!, port: +e.currentTarget.value })} />
          </Row>
          <Row label="Mode">
            <select value={editL()!.mode} onChange={(e) => setEditL({ ...editL()!, mode: e.currentTarget.value as MailListener['mode'] })}>
              <option value="terminate">terminate (TLS ends here, SNI certs)</option>
              <option value="passthrough">passthrough (raw TCP)</option>
            </select>
          </Row>
          <Row label="Backend (host:port — every mail domain on this listener goes here)">
            <input
              value={editL()!.default_backend}
              onInput={(e) => setEditL({ ...editL()!, default_backend: e.currentTarget.value })}
              placeholder="10.0.0.5:465"
            />
          </Row>
          <div class="checks">
            <Check label="Enabled" checked={editL()!.enabled} onChange={(v) => setEditL({ ...editL()!, enabled: v })} />
            {editL()!.mode === 'terminate' && (
              <Check label="Re-encrypt to backend (proxy_ssl → backend TLS port e.g. 993)" checked={editL()!.proxy_ssl} onChange={(v) => setEditL({ ...editL()!, proxy_ssl: v })} />
            )}
          </div>
          <div class="bar">
            <button type="submit" disabled={busy()}>Save & apply</button>
            <button type="button" onClick={() => setEditL(null)}>Cancel</button>
          </div>
        </form>
        </Modal>
      )}
    </section>
  )
}
