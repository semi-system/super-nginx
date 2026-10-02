import { useEffect, useState } from 'react'
import { get, post, put, del, MailListener, MailDomain, Cert } from './api'
import { Err, Row, Check, Modal, useAsync } from './ui'
import CertPicker from './CertPicker'

const emptyListener: MailListener = {
  id: 0,
  label: 'smtp',
  port: 2465,
  mode: 'terminate',
  default_backend: '',
  backend_port: 465,
  sni_route: false,
  proxy_ssl: false,
  enabled: true,
}

const knownProtocols = ['smtp', 'imap', 'pop3']

// [label, container port, backend port]: terminate + re-encrypt to the backend TLS ports
const presets = [['smtp', 2465, 465], ['imap', 2993, 993], ['pop3', 2995, 995]] as const

const emptyDomain: MailDomain = { id: 0, domain: '', backend: '', cert_id: 0 }

export default function Mail() {
  const [listeners, setListeners] = useState<MailListener[]>([])
  const [domains, setDomains] = useState<MailDomain[]>([])
  const [certs, setCerts] = useState<Cert[]>([])
  const [editL, setEditL] = useState<MailListener | null>(null)
  const [editD, setEditD] = useState<MailDomain | null>(null)
  const { error, busy, run } = useAsync()

  const reload = async () => {
    setListeners((await get('/api/v1/mail/listeners')) ?? [])
    setDomains((await get('/api/v1/mail/domains')) ?? [])
    setCerts((await get('/api/v1/certs')) ?? [])
  }
  useEffect(() => {
    run(reload)
  }, [])

  const saveL = () =>
    run(async () => {
      if (!editL) return
      if (editL.id === 0) await post('/api/v1/mail/listeners', { ...editL, id: undefined })
      else await put(`/api/v1/mail/listeners/${editL.id}`, editL)
      setEditL(null)
      await reload()
    })

  const saveD = () =>
    run(async () => {
      if (!editD) return
      if (editD.id === 0) await post('/api/v1/mail/domains', { ...editD, id: undefined })
      else await put(`/api/v1/mail/domains/${editD.id}`, editD)
      setEditD(null)
      await reload()
    })

  const addPresets = () =>
    run(async () => {
      for (const [label, port, backend_port] of presets) {
        await post('/api/v1/mail/listeners', { ...emptyListener, id: undefined, label, port, backend_port, mode: 'terminate', proxy_ssl: true })
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
      <p className="hint">
        Pure TCP/TLS proxy (nginx stream) — authentication stays on the backend mail server.
        Terminate mode ends TLS here with SNI per-domain certificates (implicit TLS: SMTPS 465,
        IMAPS 993, POP3S 995) and forwards plaintext, so the backend is its plain port (IMAP 143,
        POP3 110, SMTP 25). Tick "re-encrypt" to instead forward TLS to the backend's TLS port
        (993/995/465). Plain/STARTTLS-only ports use passthrough: the backend holds the cert.
        A domain is routed on every listener: its backend host + that listener's backend port.
      </p>
      <Err msg={error} />

      <div className="bar">
        <h3>Domains</h3>
        <button onClick={() => setEditD({ ...emptyDomain })}>+ Add domain</button>
      </div>
      <table>
        <thead>
          <tr>
            <th>Domain (SNI)</th>
            <th>Backend</th>
            <th>Certificate</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {domains.map((d) => (
            <tr key={d.id}>
              <td>{d.domain}</td>
              <td>{d.backend}</td>
              <td>{certs.find((c) => c.id === d.cert_id)?.name || '—'}</td>
              <td>
                <button onClick={() => setEditD({ ...d })}>Edit</button>{' '}
                <button onClick={() => removeD(d.id)}>Delete</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {editD && (
        <Modal onClose={() => setEditD(null)}>
        <form className="editor" onSubmit={(e) => { e.preventDefault(); saveD() }}>
          <h3>{editD.id ? 'Edit domain' : 'New mail domain'}</h3>
          <Row label="Domain (as sent in SNI, e.g. mail.example.com)">
            <input value={editD.domain} onChange={(e) => setEditD({ ...editD, domain: e.target.value })} />
          </Row>
          <Row label="Backend host (port comes from each listener)">
            <input value={editD.backend} onChange={(e) => setEditD({ ...editD, backend: e.target.value })} placeholder="10.0.0.5" />
          </Row>
          <CertPicker
            label="Certificate (for terminate listeners — can be the same cert an HTTPS host uses)"
            value={editD.cert_id}
            certs={certs}
            defaultDomains={editD.domain ? [editD.domain] : []}
            onChange={(id) => setEditD({ ...editD, cert_id: id })}
            onCertsChanged={setCerts}
          />
          <div className="bar">
            <button type="submit" disabled={busy}>Save & apply</button>
            <button type="button" onClick={() => setEditD(null)}>Cancel</button>
          </div>
        </form>
        </Modal>
      )}

      <div className="bar">
        <h3>Listeners</h3>
        <button onClick={() => setEditL({ ...emptyListener })}>+ Add listener</button>
        <button onClick={addPresets} disabled={busy} title="Creates 2465→465, 2993→993, 2995→995 (terminate, re-encrypt). Add a domain with a certificate first.">
          + SMTPS / IMAPS / POP3S
        </button>
      </div>
      <table>
        <thead>
          <tr>
            <th>Protocol</th>
            <th>Port</th>
            <th>Mode</th>
            <th>Backend port</th>
            <th>Default backend</th>
            <th>On</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {listeners.map((l) => (
            <tr key={l.id}>
              <td>{l.label}</td>
              <td>{l.port}</td>
              <td>{l.mode}{l.mode === 'passthrough' && l.sni_route ? ' (SNI route)' : ''}</td>
              <td>{l.backend_port || '—'}</td>
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

      {editL && (
        <Modal onClose={() => setEditL(null)}>
        <form className="editor" onSubmit={(e) => { e.preventDefault(); saveL() }}>
          <h3>{editL.id ? 'Edit listener' : 'New listener'}</h3>
          <Row label="Protocol (display only)">
            <select
              value={knownProtocols.includes(editL.label) ? editL.label : 'other'}
              onChange={(e) => setEditL({ ...editL, label: e.target.value === 'other' ? '' : e.target.value })}
            >
              <option value="smtp">smtp</option>
              <option value="imap">imap</option>
              <option value="pop3">pop3</option>
              <option value="other">other…</option>
            </select>
          </Row>
          {!knownProtocols.includes(editL.label) && (
            <Row label="Custom protocol name">
              <input value={editL.label} onChange={(e) => setEditL({ ...editL, label: e.target.value })} />
            </Row>
          )}
          <Row label="Container port (>1024; map from host, e.g. 465 → 2465)">
            <input type="number" value={editL.port} onChange={(e) => setEditL({ ...editL, port: +e.target.value })} />
          </Row>
          <Row label="Mode">
            <select value={editL.mode} onChange={(e) => setEditL({ ...editL, mode: e.target.value as MailListener['mode'] })}>
              <option value="terminate">terminate (TLS ends here, SNI certs)</option>
              <option value="passthrough">passthrough (raw TCP)</option>
            </select>
          </Row>
          <Row label="Backend port (domains forward here, e.g. 465 / 993 / 995)">
            <input type="number" value={editL.backend_port} onChange={(e) => setEditL({ ...editL, backend_port: +e.target.value })} />
          </Row>
          <Row label="Default backend (host:port — no-SNI clients / unmatched domains)">
            <input
              value={editL.default_backend}
              onChange={(e) => setEditL({ ...editL, default_backend: e.target.value })}
              placeholder="10.0.0.5:465"
            />
          </Row>
          <div className="checks">
            <Check label="Enabled" checked={editL.enabled} onChange={(v) => setEditL({ ...editL, enabled: v })} />
            {editL.mode === 'passthrough' && (
              <Check label="Route by SNI (ssl_preread)" checked={editL.sni_route} onChange={(v) => setEditL({ ...editL, sni_route: v })} />
            )}
            {editL.mode === 'terminate' && (
              <Check label="Re-encrypt to backend (proxy_ssl → backend TLS port e.g. 993)" checked={editL.proxy_ssl} onChange={(v) => setEditL({ ...editL, proxy_ssl: v })} />
            )}
          </div>
          <div className="bar">
            <button type="submit" disabled={busy}>Save & apply</button>
            <button type="button" onClick={() => setEditL(null)}>Cancel</button>
          </div>
        </form>
        </Modal>
      )}
    </section>
  )
}
