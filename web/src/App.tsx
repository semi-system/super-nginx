import { useEffect, useRef, useState } from 'react'
import {
  Chart,
  CategoryScale,
  Legend,
  LineController,
  LineElement,
  LinearScale,
  PointElement,
  Tooltip,
} from 'chart.js'
import { get, post } from './api'
import { Err, Row, useAsync, usePaged, Pagination } from './ui'
import Hosts from './Hosts'
import Certs from './Certs'
import Mail from './Mail'
import Streams from './Streams'
import Access from './Access'
import ConfigView from './ConfigView'
import Settings from './Settings'

// Registered piecemeal rather than importing 'chart.js/auto', which drags every
// controller (bar, pie, radar, ...) into the bundle for one line chart.
Chart.register(LineController, LineElement, PointElement, LinearScale, CategoryScale, Tooltip, Legend)

const tabs = ['Dashboard', 'Hosts', 'Certificates', 'Mail', 'Streams', 'Access', 'Config', 'Settings'] as const
type Tab = (typeof tabs)[number]

const icons: Record<Tab, string> = {
  Dashboard: '▤',
  Hosts: '🌐',
  Certificates: '🔒',
  Mail: '✉',
  Streams: '⇄',
  Access: '🛡',
  Config: '⌘',
  Settings: '⚙',
}

// Same breakpoint the design system uses to swap collapse for a drawer.
const isMobile = () => window.innerWidth < 992

const slug = (t: Tab) => t.toLowerCase()
// tab from URL hash so F5 stays on the current page (no router dependency).
function tabFromHash(): Tab {
  const h = location.hash.replace(/^#\/?/, '').toLowerCase()
  return tabs.find((t) => slug(t) === h) ?? 'Dashboard'
}

export default function App() {
  const [user, setUser] = useState<string | null>(null)
  const [checked, setChecked] = useState(false)
  const [tab, setTab] = useState<Tab>(tabFromHash)
  const [mustChange, setMustChange] = useState(false)
  const [collapsed, setCollapsed] = useState(false) // desktop: icon-only sidebar
  const [drawer, setDrawer] = useState(false) // < 992px: sliding sidebar

  useEffect(() => {
    const onHash = () => setTab(tabFromHash())
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  // The two sidebar states are exclusive: the drawer only exists below 992px,
  // the collapse only above it. Reset whichever no longer applies on resize.
  useEffect(() => {
    const onResize = () => (isMobile() ? setCollapsed(false) : setDrawer(false))
    window.addEventListener('resize', onResize)
    return () => window.removeEventListener('resize', onResize)
  }, [])

  useEffect(() => {
    get('/api/v1/me')
      .then((me) => {
        setUser(me.username)
        setMustChange(me.must_change)
      })
      .catch(() => {})
      .finally(() => setChecked(true))
  }, [])

  if (!checked) return null
  if (!user)
    return (
      <Login
        onLogin={(u, mc) => {
          setUser(u)
          setMustChange(mc)
        }}
      />
    )

  const small = collapsed ? ' small-left-menu' : ''
  const toggle = () => (isMobile() ? setDrawer(!drawer) : setCollapsed(!collapsed))

  return (
    <div className="app">
      <div id="logo" className={small}>
        {/* Cube replaces the wordmark once the sidebar collapses (see app.css). */}
        <span className="logo-cube" aria-hidden="true">
          {['front', 'back', 'right', 'left', 'top', 'bottom'].map((f) => (
            <i key={f} className={f} />
          ))}
        </span>
        <span className="big-logo">super-nginx</span>
      </div>

      <header id="header">
        <div className={`header-left${small}`}>
          <span id="toggle-left-menu" onClick={toggle} role="button" aria-label="Toggle menu">
            ☰
          </span>
        </div>
        <div className="header-right">
          <span className="hint">{user}</span>
        </div>
      </header>

      <nav id="left-menu" className={`${collapsed ? 'small-left-menu' : ''}${drawer ? ' open' : ''}`}>
        <ul>
          {tabs.map((t) => (
            <li key={t} className={t === tab ? 'active' : ''}>
              <a href={`#/${slug(t)}`} onClick={() => setDrawer(false)}>
                <i className="icon">{icons[t]}</i>
                <span>{t}</span>
              </a>
            </li>
          ))}
        </ul>
      </nav>
      <div id="sidebar-overlay" className={drawer ? 'open' : ''} onClick={() => setDrawer(false)} />

      <div id="main-content">
        <div id="page-container" className={small}>
          {mustChange && (
            <div className="alert alert-warning">
              You are using the generated password — change it in Settings.
            </div>
          )}
          {tab === 'Dashboard' && <Dashboard />}
          {tab === 'Hosts' && <Hosts />}
          {tab === 'Certificates' && <Certs />}
          {tab === 'Mail' && <Mail />}
          {tab === 'Streams' && <Streams />}
          {tab === 'Access' && <Access />}
          {tab === 'Config' && <ConfigView />}
          {tab === 'Settings' && <Settings onLogout={() => setUser(null)} />}
          <footer className="footer">
            © {new Date().getFullYear()}{' '}
            <a href="https://github.com/morningstar-sudo" target="_blank" rel="noreferrer">
              morningstar-sudo
            </a>
          </footer>
        </div>
      </div>
    </div>
  )
}

function Login({ onLogin }: { onLogin: (user: string, mustChange: boolean) => void }) {
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const { error, busy, run } = useAsync()

  const submit = () =>
    run(async () => {
      const res = await post('/api/v1/login', { Username: username, Password: password })
      onLogin(username, res.must_change)
    })

  return (
    <div className="login">
      <form className="editor" onSubmit={(e) => { e.preventDefault(); submit() }}>
        <h1>super-nginx</h1>
        <p className="hint">First boot: the admin password is printed in the container logs.</p>
        <Err msg={error} />
        <Row label="Username">
          <input value={username} onChange={(e) => setUsername(e.target.value)} />
        </Row>
        <Row label="Password">
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </Row>
        <button type="submit" disabled={busy}>Log in</button>
      </form>
    </div>
  )
}

function Dashboard() {
  const [sum, setSum] = useState<any>(null)
  const [met, setMet] = useState<any>(null)
  const [traffic, setTraffic] = useState<Traffic | null>(null)
  const { error, run } = useAsync()

  useEffect(() => {
    run(async () => {
      setSum(await get('/api/v1/summary'))
      setMet(await get('/api/v1/metrics'))
      setTraffic(await get('/api/v1/stats?hours=24'))
    })
  }, [])

  const certs: any[] = sum?.certs ?? []
  const paged = usePaged(certs, 10)

  if (error) return <Err msg={error} />
  if (!sum) return null
  const soon = (c: any) =>
    c.expires && new Date(c.expires).getTime() - Date.now() < 30 * 86400_000

  return (
    <section>
      <h2>Dashboard</h2>
      <div className="cards">
        <Stat label="nginx">
          <span className={sum.nginx.running ? 'ok' : 'error'}>
            {sum.nginx.running ? `running (pid ${sum.nginx.pid})` : 'stopped'}
          </span>
        </Stat>
        <Stat label="Hosts">{sum.hosts}</Stat>
        <Stat label="Mail listeners">{sum.listeners}</Stat>
        <Stat label="Streams">{sum.streams}</Stat>
        {met?.available && (
          <>
            <Stat label="Active conns">{met.active}</Stat>
            <Stat label="Total requests">{met.requests}</Stat>
          </>
        )}
        {traffic?.available && (
          <>
            <Stat label="Requests (24h)">{total(traffic.total.hits)}</Stat>
            <Stat label="Errors (24h)">
              <span className={total(traffic.total.e5xx) > 0 ? 'error' : ''}>
                {total(traffic.total.e4xx)} × 4xx / {total(traffic.total.e5xx)} × 5xx
              </span>
            </Stat>
            <Stat label="Sent (24h)">{bytes(total(traffic.total.bytes))}</Stat>
            <Stat label="Avg response (24h)">{weightedAvg(traffic.total)} ms</Stat>
          </>
        )}
      </div>
      {traffic?.available && Object.keys(traffic.hosts).length > 0 && (
        <div className="card">
          <div className="card-header">Per host, hourly (last 24h)</div>
          <div className="card-body">
            <TrafficChart data={traffic} />
          </div>
        </div>
      )}
      {certs.length > 0 && (
        <div className="card">
          <div className="card-header">Certificates</div>
          <div className="table-responsive">
            <table className="table table-hover">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Expires</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {paged.rows.map((c: any) => (
                  <tr key={c.name}>
                    <td>{c.name}</td>
                    <td className={soon(c) ? 'warn' : ''}>
                      {c.expires ? new Date(c.expires).toLocaleDateString() : '—'}
                    </td>
                    <td className={c.error ? 'error' : ''}>{c.error || 'ok'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {paged.pages > 1 && (
            <div className="card-footer">
              <Pagination {...paged} />
            </div>
          )}
        </div>
      )}
    </section>
  )
}

type Metrics = {
  hits: number[]
  e4xx: number[]
  e5xx: number[]
  bytes: number[]
  avg_ms: number[]
}

type Traffic = {
  available: boolean
  buckets: number[]
  total: Metrics
  hosts: Record<string, Metrics>
  names: Record<string, string>
}

type MetricKey = keyof Metrics

const metricLabels: Record<MetricKey, string> = {
  hits: 'Requests',
  e4xx: '4xx responses',
  e5xx: '5xx responses',
  bytes: 'Bytes sent',
  avg_ms: 'Avg response time (ms)',
}

const total = (xs: number[]) => xs.reduce((a, b) => a + b, 0)

// hit-weighted, so a quiet hour with one slow request cannot dominate
const weightedAvg = (m: Metrics) => {
  const hits = total(m.hits)
  return hits ? Math.round(m.avg_ms.reduce((a, ms, i) => a + ms * m.hits[i], 0) / hits) : 0
}

const bytes = (n: number) => {
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024
    i++
  }
  return `${i === 0 ? n : n.toFixed(1)} ${units[i]}`
}

// from tokens.css — primary, success, warning, danger, info, secondary
const palette = ['#0e9aee', '#22c55e', '#ffc107', '#dc3545', '#17a2b8', '#6c757d']

function TrafficChart({ data }: { data: Traffic }) {
  const ref = useRef<HTMLCanvasElement>(null)
  const [metric, setMetric] = useState<MetricKey>('hits')

  useEffect(() => {
    if (!ref.current) return
    // busiest hosts first, capped so the legend stays readable
    const hosts = Object.entries(data.hosts)
      .sort((a, b) => total(b[1].hits) - total(a[1].hits))
      .slice(0, 6)
    const chart = new Chart(ref.current, {
      type: 'line',
      data: {
        labels: data.buckets.map((t) =>
          new Date(t * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        ),
        datasets: hosts.map(([id, m], i) => ({
          label: data.names[id] ?? `host ${id}`,
          data: m[metric],
          borderColor: palette[i % palette.length],
          backgroundColor: palette[i % palette.length],
          tension: 0.3,
          pointRadius: 0,
        })),
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { mode: 'index', intersect: false },
        scales: {
          y: {
            beginAtZero: true,
            ticks: {
              precision: 0,
              callback: (v) => (metric === 'bytes' ? bytes(Number(v)) : v),
            },
          },
        },
      },
    })
    // without the destroy a re-render leaves the canvas bound and Chart.js
    // throws "Canvas is already in use"
    return () => chart.destroy()
  }, [data, metric])

  return (
    <>
      <select value={metric} onChange={(e) => setMetric(e.target.value as MetricKey)}>
        {Object.entries(metricLabels).map(([k, label]) => (
          <option key={k} value={k}>
            {label}
          </option>
        ))}
      </select>
      <div style={{ height: 260 }}>
        <canvas ref={ref} />
      </div>
    </>
  )
}

function Stat({ label, children }: { label: string; children: any }) {
  return (
    <div className="card">
      <div className="card-body">
        <b>{label}</b>
        <span className="stat">{children}</span>
      </div>
    </div>
  )
}
