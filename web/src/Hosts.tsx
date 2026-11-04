import { createEffect, createMemo, createSignal, onCleanup, onMount } from 'solid-js'
import { createMutable } from 'solid-js/store'
import { get, post, put, del, Host, Cert } from './api'
import { Err, Row, Check, Modal, Pagination, useAsync, usePaged } from './ui'
import CertPicker from './CertPicker'
import DomainInput from './DomainInput'

type AccessListOut = { id: number; name: string }

type BackendHealth = {
  address: string
  healthy: boolean
  status_code?: number
  latency_ms: number
  error?: string
  checked_at: string
}

// Preset rules: pick one and the row is filled with a sensible default value.
// Value stays editable, and "Custom…" adds a blank row for anything else.
const directivePresets: { key: string; value: string; label: string }[] = [
  { key: 'client_max_body_size', value: '100m', label: 'Max upload size' },
  { key: 'proxy_read_timeout', value: '300s', label: 'Proxy read timeout' },
  { key: 'proxy_send_timeout', value: '300s', label: 'Proxy send timeout' },
  { key: 'proxy_connect_timeout', value: '60s', label: 'Proxy connect timeout' },
  { key: 'client_body_timeout', value: '60s', label: 'Client body timeout' },
  { key: 'send_timeout', value: '60s', label: 'Send timeout' },
  { key: 'keepalive_timeout', value: '65s', label: 'Keepalive timeout' },
  { key: 'proxy_buffering', value: 'off', label: 'Disable proxy buffering' },
  { key: 'proxy_request_buffering', value: 'off', label: 'Disable request buffering' },
  { key: 'proxy_buffer_size', value: '16k', label: 'Proxy buffer size' },
  { key: 'proxy_max_temp_file_size', value: '0', label: 'Disable temp file buffering' },
  { key: 'gzip', value: 'on', label: 'Enable gzip' },
  { key: 'server_tokens', value: 'off', label: 'Hide nginx version' },
  { key: 'add_header', value: 'X-Frame-Options SAMEORIGIN always', label: 'Add header' },
]

const directiveNames = directivePresets.map((p) => p.key)

const empty: Host = {
  id: 0,
  type: 'proxy',
  domains: [],
  target: '',
  upstream_scheme: 'http',
  load_balance: 'round_robin',
  upstreams: [
    { address: '', weight: 1, max_fails: 1, fail_timeout: '10s', backup: false },
    { address: '', weight: 1, max_fails: 1, fail_timeout: '10s', backup: false },
  ],
  health_check: true,
  health_check_path: '/',
  health_check_timeout: 3,
  verify_backend_tls: false,
  backend_tls_server_name: '',
  cert_id: 0,
  isolate_certs: true,
  domain_certs: {},
  force_ssl: false,
  http2: true,
  hsts: false,
  websocket: false,
  waf: false,
  access_list_id: 0,
  cache: false,
  cache_time: '10m',
  directives: [],
  server_snippet: '',
  location_snippet: '',
  enabled: true,
}

export default function Hosts() {
  const [hosts, setHosts] = createSignal<Host[]>([])
  const [certs, setCerts] = createSignal<Cert[]>([])
  const [acls, setAcls] = createSignal<AccessListOut[]>([])
  const edit = createMutable<Host>({ ...empty, upstreams: [...empty.upstreams], directives: [], domain_certs: {} })
  const [editOpen, setEditOpen] = createSignal(false)
  const setEdit = (next: Host | null | ((current: Host | null) => Host | null)) => {
    const value = typeof next === 'function' ? next(editOpen() ? { ...edit } : null) : next
    if (!value) {
      setEditOpen(false)
      return
    }
    Object.assign(edit, value)
    setEditOpen(true)
  }
  const [health, setHealth] = createSignal<Record<number, BackendHealth[]>>({})
  const [healthBusy, setHealthBusy] = createSignal<Record<number, boolean>>({})
  const [healthError, setHealthError] = createSignal<Record<number, string>>({})
  const [search, setSearch] = createSignal('')
  const [typeFilter, setTypeFilter] = createSignal('all')
  const [stateFilter, setStateFilter] = createSignal('all')
  const [sslFilter, setSSLFilter] = createSignal('all')
  const [healthFilter, setHealthFilter] = createSignal('all')
  const { error, busy, run } = useAsync()
  const filteredHosts = createMemo(() => {
    const query = search().trim().toLowerCase()
    return hosts().filter((host) => {
      const textMatches = [
        host.domains.join(' '),
        host.type,
        host.target,
        host.upstream_scheme,
        host.load_balance,
        host.upstreams?.map((upstream) => upstream.address).join(' ') ?? '',
      ]
        .join(' ')
        .toLowerCase()
        .includes(query)
      if (!textMatches || (typeFilter() !== 'all' && host.type !== typeFilter())) return false
      if (stateFilter() === 'enabled' && !host.enabled) return false
      if (stateFilter() === 'disabled' && host.enabled) return false

      const sslMode = host.isolate_certs ? 'isolated' : host.cert_id ? 'shared' : 'none'
      if (sslFilter() !== 'all' && sslMode !== sslFilter()) return false

      if (healthFilter() !== 'all') {
        const results = health()[host.id]
        const isLoadBalancer = host.type === 'load_balancer'
        const isHealthy = isLoadBalancer && !!results?.length && results.every((backend) => backend.healthy)
        const isUnhealthy =
          isLoadBalancer && (!!healthError()[host.id] || (!!results?.length && results.some((backend) => !backend.healthy)))
        const isOff = isLoadBalancer && !host.health_check
        const isPending =
          isLoadBalancer && host.health_check && !healthError()[host.id] && !results?.length && !healthBusy()[host.id]
        if (healthFilter() === 'healthy' && !isHealthy) return false
        if (healthFilter() === 'unhealthy' && !isUnhealthy) return false
        if (healthFilter() === 'off' && !isOff) return false
        if (healthFilter() === 'pending' && !isPending) return false
      }
      return true
    })
  })
  const paged = usePaged(filteredHosts)

  const checkHealth = async (host: Host) => {
    setHealthBusy((current) => ({ ...current, [host.id]: true }))
    setHealthError((current) => ({ ...current, [host.id]: '' }))
    try {
      const result = await get<{ backends: BackendHealth[] }>(`/api/v1/hosts/${host.id}/health`)
      setHealth((current) => ({ ...current, [host.id]: result.backends }))
    } catch (e: any) {
      setHealthError((current) => ({ ...current, [host.id]: e.message || String(e) }))
    } finally {
      setHealthBusy((current) => ({ ...current, [host.id]: false }))
    }
  }

  const reload = async () => {
    setHosts((await get('/api/v1/hosts')) ?? [])
    setCerts((await get('/api/v1/certs')) ?? [])
    setAcls((await get('/api/v1/accesslists')) ?? [])
  }
  onMount(() => {
    run(reload)
  })

  createEffect(() => {
    const enabled = hosts().filter((host) => host.type === 'load_balancer' && host.health_check)
    if (enabled.length === 0) return
    const checkAll = () => enabled.forEach(checkHealth)
    checkAll()
    const timer = window.setInterval(checkAll, 30_000)
    onCleanup(() => window.clearInterval(timer))
  })

  const save = () =>
    run(async () => {
      if (!editOpen()) return
      if (edit.id === 0) await post('/api/v1/hosts', { ...edit, id: undefined })
      else await put(`/api/v1/hosts/${edit.id}`, { ...edit })
      setEdit(null)
      await reload()
    })

  const remove = (id: number) =>
    run(async () => {
      if (!confirm('Delete this host?')) return
      await del(`/api/v1/hosts/${id}`)
      await reload()
    })

  const openHost = (host: Host) =>
    setEdit({
      ...host,
      directives: host.directives ?? [],
      domain_certs: host.domain_certs ?? {},
      upstream_scheme: host.upstream_scheme || 'http',
      load_balance: host.load_balance || 'round_robin',
      upstreams: host.upstreams ?? [],
      health_check: host.health_check ?? false,
      health_check_path: host.health_check_path || '/',
      health_check_timeout: host.health_check_timeout || 3,
      verify_backend_tls: host.verify_backend_tls ?? false,
      backend_tls_server_name: host.backend_tls_server_name || '',
    })

  return (
    <section>
      <div class="bar">
        <h2>Hosts</h2>
        <button onClick={() => openHost(empty)}>+ Add host</button>
      </div>
      <div class="filter-bar" aria-label="Host filters">
        <input
          type="search"
          aria-label="Search hosts"
          placeholder="Domain, target, backend..."
          value={search()}
          onChange={(e) => {
            setSearch(e.currentTarget.value)
            paged.setPage(1)
          }}
        />
        <select
          aria-label="Filter hosts by type"
          value={typeFilter()}
          onChange={(e) => {
            setTypeFilter(e.currentTarget.value)
            paged.setPage(1)
          }}
        >
          <option value="all">All types</option>
          <option value="proxy">Proxy</option>
          <option value="load_balancer">Load balancer</option>
          <option value="redirect">Redirect</option>
          <option value="static">Static</option>
        </select>
        <select
          aria-label="Filter hosts by state"
          value={stateFilter()}
          onChange={(e) => {
            setStateFilter(e.currentTarget.value)
            paged.setPage(1)
          }}
        >
          <option value="all">All states</option>
          <option value="enabled">Enabled</option>
          <option value="disabled">Disabled</option>
        </select>
        <select
          aria-label="Filter hosts by SSL mode"
          value={sslFilter()}
          onChange={(e) => {
            setSSLFilter(e.currentTarget.value)
            paged.setPage(1)
          }}
        >
          <option value="all">All SSL modes</option>
          <option value="isolated">Isolated</option>
          <option value="shared">Shared cert</option>
          <option value="none">No certificate</option>
        </select>
        <select
          aria-label="Filter hosts by health"
          value={healthFilter()}
          onChange={(e) => {
            setHealthFilter(e.currentTarget.value)
            paged.setPage(1)
          }}
        >
          <option value="all">All health states</option>
          <option value="healthy">Healthy</option>
          <option value="unhealthy">Unhealthy</option>
          <option value="pending">Waiting for check</option>
          <option value="off">Health check off</option>
        </select>
        <button
          type="button"
          disabled={!search() && typeFilter() === 'all' && stateFilter() === 'all' && sslFilter() === 'all' && healthFilter() === 'all'}
          onClick={() => {
            setSearch('')
            setTypeFilter('all')
            setStateFilter('all')
            setSSLFilter('all')
            setHealthFilter('all')
            paged.setPage(1)
          }}
        >
          Clear
        </button>
      </div>
      <Err msg={error()} />
      <table>
        <thead>
          <tr>
            <th>Domains</th>
            <th>Type</th>
            <th>Target</th>
            <th>Health</th>
            <th>SSL</th>
            <th>WAF</th>
            <th>On</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {paged.rows().map((h) => (
            <tr>
              <td>{h.domains.join(', ')}</td>
              <td>{h.type}</td>
              <td>{h.type === 'load_balancer' ? `${h.upstreams?.length ?? 0} backends` : h.target}</td>
              <td>
                {h.type !== 'load_balancer' ? (
                  <span class="health-status neutral">{'\u2014'}</span>
                ) : !h.health_check ? (
                  <span class="health-status neutral">off</span>
                ) : healthError()[h.id] ? (
                  <button
                    type="button"
                    class="health-status error"
                    title={healthError()[h.id]}
                    onClick={() => checkHealth(h)}
                  >
                    check failed
                  </button>
                ) : health()[h.id] ? (
                  <button
                    type="button"
                    class={`health-status ${health()[h.id].every((backend) => backend.healthy) ? 'ok' : 'error'}`}
                    title={health()[h.id]
                      .map((backend) => `${backend.address}: ${backend.healthy ? `${backend.status_code} in ${backend.latency_ms}ms` : backend.error}`)
                      .join('\n')}
                    onClick={() => checkHealth(h)}
                  >
                    {health()[h.id].filter((backend) => backend.healthy).length}/{health()[h.id].length} healthy
                  </button>
                ) : (
                  <button
                    type="button"
                    class="health-status neutral"
                    disabled={healthBusy()[h.id]}
                    onClick={() => checkHealth(h)}
                  >
                    {healthBusy()[h.id] ? 'checking...' : 'check'}
                  </button>
                )}
              </td>
              <td>
                {h.isolate_certs
                  ? `${h.force_ssl ? 'forced · ' : ''}isolated ${Object.keys(h.domain_certs ?? {}).length}/${h.domains.length}`
                  : h.cert_id
                    ? h.force_ssl
                      ? 'forced'
                      : 'yes'
                    : '—'}
              </td>
              <td>{h.waf ? 'on' : 'off'}</td>
              <td>{h.enabled ? '✓' : '✗'}</td>
              <td>
                <button onClick={() => openHost(h)}>Edit</button>{' '}
                <button onClick={() => remove(h.id)}>Delete</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <Pagination {...paged} />

      {editOpen() && (
        <Modal onClose={() => setEdit(null)}>
        <form
          class="editor"
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
            <select
              value={edit.type}
              onChange={(e) => {
                const type = e.target.value as Host['type']
                setEdit({
                  ...edit,
                  type,
                  health_check: type === 'load_balancer' && edit.type !== 'load_balancer' ? true : edit.health_check,
                })
              }}
            >
              <option value="proxy">proxy</option>
              <option value="load_balancer">load balancer</option>
              <option value="redirect">redirect</option>
              <option value="static">static</option>
            </select>
          </Row>
          {edit.type === 'load_balancer' ? (
            <>
              <Row label="Upstream protocol">
                <select
                  value={edit.upstream_scheme}
                  onChange={(e) => {
                    const upstream_scheme = e.target.value as Host['upstream_scheme']
                    setEdit({
                      ...edit,
                      upstream_scheme,
                      verify_backend_tls: upstream_scheme === 'https' ? edit.verify_backend_tls : false,
                      backend_tls_server_name: upstream_scheme === 'https' ? edit.backend_tls_server_name : '',
                    })
                  }}
                >
                  <option value="http">HTTP</option>
                  <option value="https">HTTPS</option>
                </select>
              </Row>
              {edit.upstream_scheme === 'https' && (
                <>
                  <div class="checks">
                    <Check
                      label="Verify backend TLS certificate"
                      checked={edit.verify_backend_tls}
                      onChange={(verify_backend_tls) =>
                        setEdit({
                          ...edit,
                          verify_backend_tls,
                          backend_tls_server_name: verify_backend_tls
                            ? edit.backend_tls_server_name || edit.domains[0]?.replace(/^\*\./, '') || ''
                            : '',
                        })
                      }
                    />
                  </div>
                  {edit.verify_backend_tls && (
                    <Row label="Backend TLS server name">
                      <input
                        required
                        placeholder="backend.example.com"
                        value={edit.backend_tls_server_name}
                        onChange={(e) => setEdit({ ...edit, backend_tls_server_name: e.target.value.trim() })}
                      />
                      <p class="hint">
                        Every backend certificate must be valid for this name and chain to a CA in the system trust store.
                      </p>
                    </Row>
                  )}
                </>
              )}
              <Row label="Load balancing method">
                <select
                  value={edit.load_balance}
                  onChange={(e) => {
                    const load_balance = e.target.value as Host['load_balance']
                    setEdit({
                      ...edit,
                      load_balance,
                      upstreams:
                        load_balance === 'ip_hash'
                          ? edit.upstreams.map((upstream) => ({ ...upstream, backup: false }))
                          : edit.upstreams,
                    })
                  }}
                >
                  <option value="round_robin">Round robin</option>
                  <option value="least_conn">Least connections</option>
                  <option value="ip_hash">IP hash (sticky by client IP)</option>
                </select>
              </Row>
              <div class="checks">
                <Check
                  label="Active backend health check"
                  checked={edit.health_check}
                  onChange={(health_check) => setEdit({ ...edit, health_check })}
                />
              </div>
              {edit.health_check && (
                <Row label="Health check">
                  <div style={{ display: 'grid', 'grid-template-columns': 'minmax(180px, 1fr) 140px', gap: '8px' }}>
                    <input
                      required
                      placeholder="/health"
                      title="HTTP path; status 200-399 is healthy"
                      value={edit.health_check_path}
                      onChange={(e) => setEdit({ ...edit, health_check_path: e.target.value })}
                    />
                    <input
                      type="number"
                      min={1}
                      max={30}
                      title="Timeout in seconds"
                      value={edit.health_check_timeout}
                      onChange={(e) => setEdit({ ...edit, health_check_timeout: +e.target.value })}
                    />
                  </div>
                  <p class="hint">
                    GET path / timeout in seconds. Status 200-399 is healthy; the Hosts page refreshes probes every 30 seconds.
                  </p>
                </Row>
              )}
              <Row label="Backends (at least two)">
                <div>
                  {edit.upstreams.map((upstream, i) => (
                    <div
                      style={{ display: 'grid', 'grid-template-columns': 'minmax(180px, 2fr) 80px 90px 100px auto auto', gap: '6px', 'margin-bottom': '6px', 'align-items': 'center' }}
                    >
                      <input
                        required
                        placeholder="app-1:3000"
                        title="Backend address (host:port)"
                        value={upstream.address}
                        onChange={(e) => {
                          const upstreams = [...edit.upstreams]
                          upstreams[i] = { ...upstream, address: e.target.value }
                          setEdit({ ...edit, upstreams })
                        }}
                      />
                      <input
                        type="number"
                        min={0}
                        max={1000}
                        title="Weight (0 uses the nginx default)"
                        value={upstream.weight}
                        onChange={(e) => {
                          const upstreams = [...edit.upstreams]
                          upstreams[i] = { ...upstream, weight: +e.target.value }
                          setEdit({ ...edit, upstreams })
                        }}
                      />
                      <input
                        type="number"
                        min={0}
                        max={1000}
                        title="Failures before the backend is considered unavailable"
                        value={upstream.max_fails}
                        onChange={(e) => {
                          const upstreams = [...edit.upstreams]
                          upstreams[i] = { ...upstream, max_fails: +e.target.value }
                          setEdit({ ...edit, upstreams })
                        }}
                      />
                      <input
                        placeholder="10s"
                        title="Failure timeout (for example 10s or 1m)"
                        value={upstream.fail_timeout}
                        onChange={(e) => {
                          const upstreams = [...edit.upstreams]
                          upstreams[i] = { ...upstream, fail_timeout: e.target.value }
                          setEdit({ ...edit, upstreams })
                        }}
                      />
                      <label class="check" title="Only use this backend when primary backends are unavailable">
                        <input
                          type="checkbox"
                          checked={upstream.backup}
                          disabled={edit.load_balance === 'ip_hash'}
                          onChange={(e) => {
                            const upstreams = [...edit.upstreams]
                            upstreams[i] = { ...upstream, backup: e.target.checked }
                            setEdit({ ...edit, upstreams })
                          }}
                        />
                        backup
                      </label>
                      <button
                        type="button"
                        aria-label={`Remove backend ${i + 1}`}
                        onClick={() => setEdit({ ...edit, upstreams: edit.upstreams.filter((_, j) => j !== i) })}
                      >
                        ×
                      </button>
                    </div>
                  ))}
                  <p class="hint">Columns: address, weight, max failures, failure timeout, backup.</p>
                  <button
                    type="button"
                    onClick={() =>
                      setEdit({
                        ...edit,
                        upstreams: [
                          ...edit.upstreams,
                          { address: '', weight: 1, max_fails: 1, fail_timeout: '10s', backup: false },
                        ],
                      })
                    }
                  >
                    + Add backend
                  </button>
                </div>
              </Row>
            </>
          ) : (
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
          )}
          <CertPicker
            value={edit.cert_id}
            certs={certs()}
            defaultDomains={edit.domains}
            noneLabel="— none (http only) —"
            onChange={(id) => setEdit((current) => (current ? { ...current, cert_id: id } : current))}
            onCertsChanged={setCerts}
            isolate={edit.isolate_certs}
            domainCerts={edit.domain_certs}
            onIsolateChange={(isolate_certs) =>
              setEdit((current) => (current ? { ...current, isolate_certs } : current))
            }
            onDomainCertsChange={(domain_certs) =>
              setEdit((current) => (current ? { ...current, cert_id: 0, domain_certs } : current))
            }
          />
          <Row label="Access list">
            <select value={edit.access_list_id} onChange={(e) => setEdit({ ...edit, access_list_id: +e.target.value })}>
              <option value={0}>— none —</option>
              {acls().map((l) => (
                <option value={l.id}>
                  {l.name}
                </option>
              ))}
            </select>
          </Row>
          <div class="checks">
            <Check label="Enabled" checked={edit.enabled} onChange={(v) => setEdit({ ...edit, enabled: v })} />
            <Check label="Force SSL" checked={edit.force_ssl} onChange={(v) => setEdit({ ...edit, force_ssl: v })} />
            <Check label="HTTP/2" checked={edit.http2} onChange={(v) => setEdit({ ...edit, http2: v })} />
            <Check label="HSTS" checked={edit.hsts} onChange={(v) => setEdit({ ...edit, hsts: v })} />
            <Check label="Websockets" checked={edit.websocket} onChange={(v) => setEdit({ ...edit, websocket: v })} />
            <Check label="WAF (ModSecurity + CRS)" checked={edit.waf} onChange={(v) => setEdit({ ...edit, waf: v })} />
            {(edit.type === 'proxy' || edit.type === 'load_balancer') && (
              <Check label="Cache" checked={edit.cache} onChange={(v) => setEdit({ ...edit, cache: v })} />
            )}
          </div>
          <Row label="Directives (server context — rendered as `name value;`)">
            <datalist id="nginx-directives">
              {directiveNames.map((d) => (
                <option value={d} />
              ))}
            </datalist>
            <div>
              {edit.directives.map((d, i) => (
                <div style={{ display: 'flex', gap: '6px', 'margin-bottom': '6px' }}>
                  <input
                    list="nginx-directives"
                    placeholder="client_max_body_size"
                    value={d.key}
                    onChange={(e) => {
                      const directives = [...edit.directives]
                      directives[i] = { ...d, key: e.target.value }
                      setEdit({ ...edit, directives })
                    }}
                  />
                  <input
                    placeholder="100m"
                    value={d.value}
                    onChange={(e) => {
                      const directives = [...edit.directives]
                      directives[i] = { ...d, value: e.target.value }
                      setEdit({ ...edit, directives })
                    }}
                  />
                  <button type="button" onClick={() => setEdit({ ...edit, directives: edit.directives.filter((_, j) => j !== i) })}>
                    ✕
                  </button>
                </div>
              ))}
              <select
                value=""
                onChange={(e) => {
                  const p = directivePresets.find((x) => x.key === e.target.value)
                  const row = p ? { key: p.key, value: p.value } : { key: '', value: '' }
                  setEdit({ ...edit, directives: [...edit.directives, row] })
                }}
              >
                <option value="">+ add rule…</option>
                {directivePresets.map((p) => (
                  <option value={p.key}>
                    {p.label} ({p.key} {p.value})
                  </option>
                ))}
                <option value="__custom__">Custom…</option>
              </select>
            </div>
          </Row>
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
          <div class="bar">
            <button type="submit" disabled={busy()}>
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
