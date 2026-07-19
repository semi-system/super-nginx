import { useEffect, useState } from 'react'
import { get, post, put } from './api'
import { Err, Row, Check, useAsync } from './ui'

export default function Settings({ onLogout }: { onLogout: () => void }) {
  const [email, setEmail] = useState('')
  const [staging, setStaging] = useState(false)
  const [oldPw, setOldPw] = useState('')
  const [newPw, setNewPw] = useState('')
  const [msg, setMsg] = useState('')
  const { error, busy, run } = useAsync()

  useEffect(() => {
    run(async () => {
      const s = await get('/api/v1/settings')
      setEmail(s.acme_email || '')
      setStaging(!!s.acme_staging)
    })
  }, [])

  const saveSettings = () =>
    run(async () => {
      await put('/api/v1/settings', { acme_email: email, acme_staging: staging })
      setMsg('Settings saved')
    })

  const changePw = () =>
    run(async () => {
      await post('/api/v1/password', { Old: oldPw, New: newPw })
      setOldPw('')
      setNewPw('')
      setMsg('Password changed')
    })

  const logout = () =>
    run(async () => {
      await post('/api/v1/logout')
      onLogout()
    })

  return (
    <section>
      <h2>Settings</h2>
      <Err msg={error} />
      {msg && <p className="hint">{msg}</p>}

      <form className="editor" onSubmit={(e) => { e.preventDefault(); saveSettings() }}>
        <h3>ACME (Let's Encrypt)</h3>
        <Row label="Account email">
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
        </Row>
        <div className="checks">
          <Check label="Use staging CA (testing — untrusted certs, high rate limits)" checked={staging} onChange={setStaging} />
        </div>
        <button type="submit" disabled={busy}>Save</button>
      </form>

      <form className="editor" onSubmit={(e) => { e.preventDefault(); changePw() }}>
        <h3>Change password</h3>
        <Row label="Current password">
          <input type="password" value={oldPw} onChange={(e) => setOldPw(e.target.value)} />
        </Row>
        <Row label="New password (min 8 chars)">
          <input type="password" value={newPw} onChange={(e) => setNewPw(e.target.value)} />
        </Row>
        <button type="submit" disabled={busy}>Change</button>
      </form>

      <div className="editor">
        <h3>Backup & restore</h3>
        <p className="hint">
          Backup = state + certificates + ACME account (tar.gz). Rendered config is regenerated on
          restore.
        </p>
        <div className="bar">
          <a href="/api/v1/backup" download>
            <button type="button">Download backup</button>
          </a>
          <label>
            <input
              type="file"
              accept=".gz,.tgz,application/gzip"
              style={{ display: 'none' }}
              onChange={(e) => {
                const f = e.target.files?.[0]
                if (!f || !confirm('Restore this backup? Current state will be replaced.')) return
                run(async () => {
                  const res = await fetch('/api/v1/restore', { method: 'POST', body: f })
                  const data = await res.json()
                  if (!res.ok) throw new Error(data.error || res.statusText)
                  setMsg(`Restored ${data.files} files`)
                })
              }}
            />
            <button type="button" onClick={(e) => (e.currentTarget.parentElement!.querySelector('input') as HTMLInputElement).click()}>
              Restore from file…
            </button>
          </label>
        </div>
      </div>

      <div className="editor">
        <h3>Audit log</h3>
        <AuditLog />
      </div>

      <div className="editor">
        <h3>Session</h3>
        <button onClick={logout}>Log out</button>
      </div>
    </section>
  )
}

function AuditLog() {
  const [lines, setLines] = useState<string[]>([])
  useEffect(() => {
    get('/api/v1/audit').then(setLines).catch(() => {})
  }, [])
  if (!lines.length) return <p className="hint">No entries yet.</p>
  return <pre>{lines.join('\n')}</pre>
}
