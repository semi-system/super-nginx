import { createEffect, createSignal, JSX, onCleanup, onMount } from 'solid-js'
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
  const [user, setUser] = createSignal<string | null>(null)
  const [checked, setChecked] = createSignal(false)
  const [tab, setTab] = createSignal<Tab>(tabFromHash())
  const [mustChange, setMustChange] = createSignal(false)
  const [collapsed, setCollapsed] = createSignal(false) // desktop: icon-only sidebar
  const [drawer, setDrawer] = createSignal(false) // < 992px: sliding sidebar

  onMount(() => {
    const onHash = () => setTab(tabFromHash())
    window.addEventListener('hashchange', onHash)
    onCleanup(() => window.removeEventListener('hashchange', onHash))
  })

  // The two sidebar states are exclusive: the drawer only exists below 992px,
  // the collapse only above it. Reset whichever no longer applies on resize.
  onMount(() => {
    const onResize = () => (isMobile() ? setCollapsed(false) : setDrawer(false))
    window.addEventListener('resize', onResize)
    onCleanup(() => window.removeEventListener('resize', onResize))
  })

  onMount(() => {
    get('/api/v1/me')
      .then((me) => {
        setUser(me.username)
        setMustChange(me.must_change)
      })
      .catch(() => {})
      .finally(() => setChecked(true))
  })

  const small = () => collapsed() ? ' small-left-menu' : ''
  const toggle = () => (isMobile() ? setDrawer(!drawer()) : setCollapsed(!collapsed()))

  return (
    <>{checked() && (user() ? <div class="app">
      <div id="logo" class={small()}>
        {/* Cube replaces the wordmark once the sidebar collapses (see app.css). */}
        <span class="logo-cube" aria-hidden="true">
          {['front', 'back', 'right', 'left', 'top', 'bottom'].map((f) => (
            <i class={f} />
          ))}
        </span>
        <span class="big-logo">super-nginx</span>
      </div>

      <header id="header">
        <div class={`header-left${small()}`}>
          <span id="toggle-left-menu" onClick={toggle} role="button" aria-label="Toggle menu">
            ☰
          </span>
        </div>
        <div class="header-right">
          <span class="hint">{user()}</span>
        </div>
      </header>

      <nav id="left-menu" class={`${collapsed() ? 'small-left-menu' : ''}${drawer() ? ' open' : ''}`}>
        <ul>
          {tabs.map((t) => (
            <li class={t === tab() ? 'active' : ''}>
              <a href={`#/${slug(t)}`} onClick={() => setDrawer(false)}>
                <i class="icon">{icons[t]}</i>
                <span>{t}</span>
              </a>
            </li>
          ))}
        </ul>
      </nav>
      <div id="sidebar-overlay" class={drawer() ? 'open' : ''} onClick={() => setDrawer(false)} />

      <div id="main-content">
        <div id="page-container" class={small()}>
          {mustChange() && (
            <div class="alert alert-warning">
              You are using the generated password — change it in Settings.
            </div>
          )}
          {tab() === 'Dashboard' && <Dashboard />}
          {tab() === 'Hosts' && <Hosts />}
          {tab() === 'Certificates' && <Certs />}
          {tab() === 'Mail' && <Mail />}
          {tab() === 'Streams' && <Streams />}
          {tab() === 'Access' && <Access />}
          {tab() === 'Config' && <ConfigView />}
          {tab() === 'Settings' && <Settings onLogout={() => setUser(null)} />}
          <footer class="footer">
            © {new Date().getFullYear()}{' '}
            <a href="https://github.com/morningstar-sudo" target="_blank" rel="noreferrer">
              morningstar-sudo
            </a>
          </footer>
        </div>
      </div>
    </div> : <Login onLogin={(name, changeRequired) => { setUser(name); setMustChange(changeRequired) }} />)}</>
  )
}

function Login(props: { onLogin: (user: string, mustChange: boolean) => void }) {
  const [username, setUsername] = createSignal('admin')
  const [password, setPassword] = createSignal('')
  const { error, busy, run } = useAsync()

  const submit = () =>
    run(async () => {
      const res = await post('/api/v1/login', { Username: username(), Password: password() })
      props.onLogin(username(), res.must_change)
    })

  return (
    <div class="login">
      <form class="editor" onSubmit={(e) => { e.preventDefault(); submit() }}>
        <h1>super-nginx</h1>
        <p class="hint">First boot: the admin password is printed in the container logs.</p>
        <Err msg={error()} />
        <Row label="Username">
          <input value={username()} onInput={(e) => setUsername(e.currentTarget.value)} />
        </Row>
        <Row label="Password">
          <input type="password" value={password()} onInput={(e) => setPassword(e.currentTarget.value)} />
        </Row>
        <button type="submit" disabled={busy()}>Log in</button>
      </form>
    </div>
  )
}

function Dashboard() {
  const [sum, setSum] = createSignal<any>(null)
  const [met, setMet] = createSignal<any>(null)
  const [traffic, setTraffic] = createSignal<Traffic | null>(null)
  const { error, run } = useAsync()

  onMount(() => {
    run(async () => {
      setSum(await get('/api/v1/summary'))
      setMet(await get('/api/v1/metrics'))
      setTraffic(await get('/api/v1/stats?hours=24'))
    })
  })

  const certs = () => (sum()?.certs ?? []) as any[]
  const paged = usePaged(certs, 10)

  const soon = (c: any) =>
    c.expires && new Date(c.expires).getTime() - Date.now() < 30 * 86400_000

  return (
    <section>
      <Err msg={error()} />
      {sum() && <><h2>Dashboard</h2>
      <div class="cards">
        <Stat label="nginx">
          <span class={sum().nginx.running ? 'ok' : 'error'}>
            {sum().nginx.running ? `running (pid ${sum().nginx.pid})` : 'stopped'}
          </span>
        </Stat>
        <Stat label="Hosts">{sum().hosts}</Stat>
        <Stat label="Mail listeners">{sum().listeners}</Stat>
        <Stat label="Streams">{sum().streams}</Stat>
        {met()?.available && (
          <>
            <Stat label="Active conns">{met().active}</Stat>
            <Stat label="Total requests">{met().requests}</Stat>
          </>
        )}
        {traffic()?.available && (
          <>
            <Stat label="Requests (24h)">{total(traffic()!.total.hits)}</Stat>
            <Stat label="Errors (24h)">
              <span class={total(traffic()!.total.e5xx) > 0 ? 'error' : ''}>
                {total(traffic()!.total.e4xx)} × 4xx / {total(traffic()!.total.e5xx)} × 5xx
              </span>
            </Stat>
            <Stat label="Sent (24h)">{bytes(total(traffic()!.total.bytes))}</Stat>
            <Stat label="Avg response (24h)">{weightedAvg(traffic()!.total)} ms</Stat>
          </>
        )}
      </div>
      {traffic()?.available && Object.keys(traffic()!.hosts).length > 0 && (
        <div class="card">
          <div class="card-header">Per host, hourly (last 24h)</div>
          <div class="card-body">
            <TrafficChart data={traffic()!} />
          </div>
        </div>
      )}
      {certs().length > 0 && (
        <div class="card">
          <div class="card-header">Certificates</div>
          <div class="table-responsive">
            <table class="table table-hover">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Expires</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {paged.rows().map((c: any) => (
                  <tr>
                    <td>{c.name}</td>
                    <td class={soon(c) ? 'warn' : ''}>
                      {c.expires ? new Date(c.expires).toLocaleDateString() : '—'}
                    </td>
                    <td class={c.error ? 'error' : ''}>{c.error || 'ok'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {paged.pages() > 1 && (
            <div class="card-footer">
              <Pagination {...paged} />
            </div>
          )}
        </div>
      )}</>}
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

function TrafficChart(props: { data: Traffic }) {
  let canvas!: HTMLCanvasElement
  const [metric, setMetric] = createSignal<MetricKey>('hits')

  createEffect(() => {
    const selectedMetric = metric()
    // busiest hosts first, capped so the legend stays readable
    const hosts = Object.entries(props.data.hosts)
      .sort((a, b) => total(b[1].hits) - total(a[1].hits))
      .slice(0, 6)
    const chart = new Chart(canvas, {
      type: 'line',
      data: {
        labels: props.data.buckets.map((t) =>
          new Date(t * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        ),
        datasets: hosts.map(([id, m], i) => ({
          label: props.data.names[id] ?? `host ${id}`,
          data: m[selectedMetric],
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
              callback: (v) => (selectedMetric === 'bytes' ? bytes(Number(v)) : v),
            },
          },
        },
      },
    })
    // without the destroy a re-render leaves the canvas bound and Chart.js
    // throws "Canvas is already in use"
    onCleanup(() => chart.destroy())
  })

  return (
    <>
      <select value={metric()} onChange={(e) => setMetric(e.currentTarget.value as MetricKey)}>
        {Object.entries(metricLabels).map(([k, label]) => (
          <option value={k}>
            {label}
          </option>
        ))}
      </select>
      <div style={{ height: '260px' }}>
        <canvas ref={canvas} />
      </div>
    </>
  )
}

function Stat(props: { label: string; children: JSX.Element }) {
  return (
    <div class="card">
      <div class="card-body">
        <b>{props.label}</b>
        <span class="stat">{props.children}</span>
      </div>
    </div>
  )
}
