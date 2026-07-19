import { useEffect, useState } from 'react'
import { get, post } from './api'
import { Err, Row, useAsync } from './ui'
import Hosts from './Hosts'
import Certs from './Certs'
import Mail from './Mail'
import Streams from './Streams'
import Access from './Access'
import ConfigView from './ConfigView'
import Settings from './Settings'

const tabs = ['Dashboard', 'Hosts', 'Certificates', 'Mail', 'Streams', 'Access', 'Config', 'Settings'] as const
type Tab = (typeof tabs)[number]

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

  useEffect(() => {
    const onHash = () => setTab(tabFromHash())
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
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

  return (
    <div className="app">
      <nav>
        <span className="brand">super-nginx</span>
        {tabs.map((t) => (
          <a key={t} className={t === tab ? 'active' : ''} href={`#/${slug(t)}`}>
            {t}
          </a>
        ))}
      </nav>
      {mustChange && (
        <p className="warn">You are using the generated password — change it in Settings.</p>
      )}
      <main>
        {tab === 'Dashboard' && <Dashboard />}
        {tab === 'Hosts' && <Hosts />}
        {tab === 'Certificates' && <Certs />}
        {tab === 'Mail' && <Mail />}
        {tab === 'Streams' && <Streams />}
        {tab === 'Access' && <Access />}
        {tab === 'Config' && <ConfigView />}
        {tab === 'Settings' && <Settings onLogout={() => setUser(null)} />}
      </main>
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

  if (error) return <Err msg={error} />
  if (!sum) return null
  const soon = (c: any) =>
    c.expires && new Date(c.expires).getTime() - Date.now() < 30 * 86400_000

  return (
    <section>
      <h2>Dashboard</h2>
      <div className="cards">
        <div className="card">
          <b>nginx</b>
          <span className={sum.nginx.running ? 'ok' : 'error'}>
            {sum.nginx.running ? `running (pid ${sum.nginx.pid})` : 'stopped'}
          </span>
        </div>
        <div className="card">
          <b>Hosts</b>
          <span>{sum.hosts}</span>
        </div>
        <div className="card">
          <b>Mail listeners</b>
          <span>{sum.listeners}</span>
        </div>
        <div className="card">
          <b>Streams</b>
          <span>{sum.streams}</span>
        </div>
        {met?.available && (
          <>
            <div className="card">
              <b>Active conns</b>
              <span>{met.active}</span>
            </div>
            <div className="card">
              <b>Total requests</b>
              <span>{met.requests}</span>
            </div>
          </>
        )}
      </div>
      {(sum.certs || []).length > 0 && (
        <>
          <h3>Certificates</h3>
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Expires</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {sum.certs.map((c: any) => (
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
        </>
      )}
    </section>
  )
}
