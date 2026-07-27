import { useEffect, useState } from 'react'
import { get, post } from './api'
import { Err, Row, useAsync, usePaged, Pagination } from './ui'
import Hosts from './Hosts'
import Certs from './Certs'
import Mail from './Mail'
import Streams from './Streams'
import Access from './Access'
import ConfigView from './ConfigView'
import Settings from './Settings'

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
  const { error, run } = useAsync()

  useEffect(() => {
    run(async () => {
      setSum(await get('/api/v1/summary'))
      setMet(await get('/api/v1/metrics'))
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
      </div>
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
