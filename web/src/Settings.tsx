import { useEffect, useRef, useState } from 'react'
import { get, post, put } from './api'
import { Err, Row, Check, useAsync } from './ui'

export default function Settings({ onLogout }: { onLogout: () => void }) {
  const [email, setEmail] = useState('')
  const [staging, setStaging] = useState(false)
  const [oldPw, setOldPw] = useState('')
  const [newPw, setNewPw] = useState('')
  const [backupPw, setBackupPw] = useState('')
  const [msg, setMsg] = useState('')
  const fileInput = useRef<HTMLInputElement>(null)
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
          Backup = data + certificates + ACME account, always encrypted (AES-256-GCM). With a
          password it is portable — restore it anywhere with the same password. Without a password
          it is encrypted with a per-instance key, so it restores only on this instance. Use the
          same password to restore.
        </p>
        <Row label="Backup password (optional)">
          <input
            type="password"
            value={backupPw}
            onChange={(e) => setBackupPw(e.target.value)}
            placeholder="leave empty for per-instance key"
          />
        </Row>
        <div className="bar">
          <button
            type="button"
            onClick={() =>
              run(async () => {
                const res = await fetch('/api/v1/backup', {
                  method: 'POST',
                  headers: { 'X-Backup-Password': backupPw },
                })
                if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || res.statusText)
                const blob = await res.blob()
                const cd = res.headers.get('Content-Disposition') || ''
                const name = /filename="([^"]+)"/.exec(cd)?.[1] || 'super-nginx-backup.snb'
                const url = URL.createObjectURL(blob)
                const a = document.createElement('a')
                a.href = url
                a.download = name
                a.click()
                URL.revokeObjectURL(url)
                setMsg('Backup downloaded')
              })
            }
          >
            Download backup
          </button>
          <input
            ref={fileInput}
            type="file"
            accept=".snb"
            style={{ display: 'none' }}
            onChange={(e) => {
              const f = e.target.files?.[0]
              e.target.value = '' // so picking the same file twice still fires
              if (!f || !confirm('Restore this backup? Current data will be replaced.')) return
              run(async () => {
                const res = await fetch('/api/v1/restore', {
                  method: 'POST',
                  headers: { 'X-Backup-Password': backupPw },
                  body: f,
                })
                const data = await res.json()
                if (!res.ok) throw new Error(data.error || res.statusText)
                setMsg(`Restored (${data.files} cert files)`)
              })
            }}
          />
          <button type="button" onClick={() => fileInput.current?.click()}>
            Restore from file…
          </button>
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
