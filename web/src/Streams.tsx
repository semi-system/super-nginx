import { useEffect, useState } from 'react'
import { get, post, put, del, StreamRule } from './api'
import { Err, Row, Check, useAsync } from './ui'

const empty: StreamRule = { id: 0, port: 15000, udp: false, backend: '', enabled: true }

export default function Streams() {
  const [rules, setRules] = useState<StreamRule[]>([])
  const [edit, setEdit] = useState<StreamRule | null>(null)
  const { error, busy, run } = useAsync()

  const reload = async () => setRules((await get('/api/v1/streams')) ?? [])
  useEffect(() => {
    run(reload)
  }, [])

  const save = () =>
    run(async () => {
      if (!edit) return
      if (edit.id === 0) await post('/api/v1/streams', { ...edit, id: undefined })
      else await put(`/api/v1/streams/${edit.id}`, edit)
      setEdit(null)
      await reload()
    })

  const remove = (id: number) =>
    run(async () => {
      if (!confirm('Delete stream?')) return
      await del(`/api/v1/streams/${id}`)
      await reload()
    })

  return (
    <section>
      <div className="bar">
        <h2>Streams (TCP/UDP forward)</h2>
        <button onClick={() => setEdit({ ...empty })}>+ Add stream</button>
      </div>
      <Err msg={error} />
      <table>
        <thead>
          <tr>
            <th>Port</th>
            <th>Proto</th>
            <th>Backend</th>
            <th>On</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {rules.map((r) => (
            <tr key={r.id}>
              <td>{r.port}</td>
              <td>{r.udp ? 'udp' : 'tcp'}</td>
              <td>{r.backend}</td>
              <td>{r.enabled ? '✓' : '✗'}</td>
              <td>
                <button onClick={() => setEdit({ ...r })}>Edit</button>{' '}
                <button onClick={() => remove(r.id)}>Delete</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {edit && (
        <form className="editor" onSubmit={(e) => { e.preventDefault(); save() }}>
          <h3>{edit.id ? 'Edit stream' : 'New stream'}</h3>
          <Row label="Container port (>1024)">
            <input type="number" value={edit.port} onChange={(e) => setEdit({ ...edit, port: +e.target.value })} />
          </Row>
          <Row label="Backend (host:port)">
            <input value={edit.backend} onChange={(e) => setEdit({ ...edit, backend: e.target.value })} />
          </Row>
          <div className="checks">
            <Check label="UDP" checked={edit.udp} onChange={(v) => setEdit({ ...edit, udp: v })} />
            <Check label="Enabled" checked={edit.enabled} onChange={(v) => setEdit({ ...edit, enabled: v })} />
          </div>
          <div className="bar">
            <button type="submit" disabled={busy}>Save & apply</button>
            <button type="button" onClick={() => setEdit(null)}>Cancel</button>
          </div>
        </form>
      )}
    </section>
  )
}
