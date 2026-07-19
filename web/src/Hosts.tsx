import { useEffect, useState } from 'react'
import { get, post, put, del, Host, Cert } from './api'
import { Err, Row, Check, Modal, useAsync } from './ui'
import CertPicker from './CertPicker'
import DomainInput from './DomainInput'

type AccessListOut = { id: number; name: string }

const empty: Host = {
  id: 0,
  type: 'proxy',
  domains: [],
  target: '',
  cert_id: 0,
  force_ssl: false,
  http2: true,
  hsts: false,
  websocket: false,
  waf: false,
  access_list_id: 0,
  cache: false,
  cache_time: '10m',
  server_snippet: '',
  location_snippet: '',
  enabled: true,
}

export default function Hosts() {
  const [hosts, setHosts] = useState<Host[]>([])
  const [certs, setCerts] = useState<Cert[]>([])
  const [acls, setAcls] = useState<AccessListOut[]>([])
  const [edit, setEdit] = useState<Host | null>(null)
  const { error, busy, run } = useAsync()

  const reload = async () => {
    setHosts((await get('/api/v1/hosts')) ?? [])
    setCerts((await get('/api/v1/certs')) ?? [])
    setAcls((await get('/api/v1/accesslists')) ?? [])
  }
  useEffect(() => {
    run(reload)
  }, [])

  const save = () =>
    run(async () => {
      if (!edit) return
      if (edit.id === 0) await post('/api/v1/hosts', { ...edit, id: undefined })
      else await put(`/api/v1/hosts/${edit.id}`, edit)
      setEdit(null)
      await reload()
    })

  const remove = (id: number) =>
    run(async () => {
      if (!confirm('Delete this host?')) return
      await del(`/api/v1/hosts/${id}`)
      await reload()
    })

  return (
    <section>
      <div className="bar">
        <h2>Hosts</h2>
        <button onClick={() => setEdit({ ...empty })}>+ Add host</button>
      </div>
      <Err msg={error} />
      <table>
        <thead>
          <tr>
            <th>Domains</th>
            <th>Type</th>
            <th>Target</th>
            <th>SSL</th>
            <th>WAF</th>
            <th>On</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {hosts.map((h) => (
            <tr key={h.id}>
              <td>{h.domains.join(', ')}</td>
              <td>{h.type}</td>
              <td>{h.target}</td>
              <td>{h.cert_id ? (h.force_ssl ? 'forced' : 'yes') : '—'}</td>
              <td>{h.waf ? 'on' : 'off'}</td>
              <td>{h.enabled ? '✓' : '✗'}</td>
              <td>
                <button onClick={() => setEdit({ ...h })}>Edit</button>{' '}
                <button onClick={() => remove(h.id)}>Delete</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {edit && (
        <Modal onClose={() => setEdit(null)}>
        <form
          className="editor"
          onSubmit={(e) => {
            e.preventDefault()
            save()
          }}
        >
          <h3>{edit.id ? `Edit host ${edit.id}` : 'New host'}</h3>
          <Row label="Domains">
            <DomainInput value={edit.domains} onChange={(domains) => setEdit({ ...edit, domains })} />
          </Row>
          <Row label="Type">
            <select value={edit.type} onChange={(e) => setEdit({ ...edit, type: e.target.value as Host['type'] })}>
              <option value="proxy">proxy</option>
              <option value="redirect">redirect</option>
              <option value="static">static</option>
            </select>
          </Row>
          <Row
            label={
              edit.type === 'proxy'
                ? 'Upstream (http://host:port)'
                : edit.type === 'redirect'
                  ? 'Redirect to (URL)'
                  : 'Directory under /data/www'
            }
          >
            <input value={edit.target} onChange={(e) => setEdit({ ...edit, target: e.target.value })} />
          </Row>
          <CertPicker
            value={edit.cert_id}
            certs={certs}
            defaultDomains={edit.domains}
            noneLabel="— none (http only) —"
            onChange={(id) => setEdit({ ...edit, cert_id: id })}
            onCertsChanged={setCerts}
          />
          <Row label="Access list">
            <select value={edit.access_list_id} onChange={(e) => setEdit({ ...edit, access_list_id: +e.target.value })}>
              <option value={0}>— none —</option>
              {acls.map((l) => (
                <option key={l.id} value={l.id}>
                  {l.name}
                </option>
              ))}
            </select>
          </Row>
          <div className="checks">
            <Check label="Enabled" checked={edit.enabled} onChange={(v) => setEdit({ ...edit, enabled: v })} />
            <Check label="Force SSL" checked={edit.force_ssl} onChange={(v) => setEdit({ ...edit, force_ssl: v })} />
            <Check label="HTTP/2" checked={edit.http2} onChange={(v) => setEdit({ ...edit, http2: v })} />
            <Check label="HSTS" checked={edit.hsts} onChange={(v) => setEdit({ ...edit, hsts: v })} />
            <Check label="Websockets" checked={edit.websocket} onChange={(v) => setEdit({ ...edit, websocket: v })} />
            <Check label="WAF (ModSecurity + CRS)" checked={edit.waf} onChange={(v) => setEdit({ ...edit, waf: v })} />
            {edit.type === 'proxy' && (
              <Check label="Cache" checked={edit.cache} onChange={(v) => setEdit({ ...edit, cache: v })} />
            )}
          </div>
          <Row label="Custom nginx — server context">
            <textarea
              rows={3}
              value={edit.server_snippet}
              onChange={(e) => setEdit({ ...edit, server_snippet: e.target.value })}
              placeholder="client_max_body_size 100m;"
            />
          </Row>
          <Row label="Custom nginx — location context">
            <textarea
              rows={3}
              value={edit.location_snippet}
              onChange={(e) => setEdit({ ...edit, location_snippet: e.target.value })}
              placeholder="proxy_read_timeout 300s;"
            />
          </Row>
          <div className="bar">
            <button type="submit" disabled={busy}>
              Save & apply
            </button>
            <button type="button" onClick={() => setEdit(null)}>
              Cancel
            </button>
          </div>
        </form>
        </Modal>
      )}
    </section>
  )
}
