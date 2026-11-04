import { createSignal, onMount } from 'solid-js'
import { get, post, put, del, StreamRule } from './api'
import { Err, Row, Check, Modal, Pagination, useAsync, usePaged } from './ui'

const empty: StreamRule = { id: 0, port: 15000, udp: false, backend: '', enabled: true }

export default function Streams() {
  const [rules, setRules] = createSignal<StreamRule[]>([])
  const [edit, setEdit] = createSignal<StreamRule | null>(null)
  const { error, busy, run } = useAsync()
  const paged = usePaged(rules)

  const reload = async () => setRules((await get('/api/v1/streams')) ?? [])
  onMount(() => {
    run(reload)
  })

  const save = () =>
    run(async () => {
      const current = edit()
      if (!current) return
      if (current.id === 0) await post('/api/v1/streams', { ...current, id: undefined })
      else await put(`/api/v1/streams/${current.id}`, current)
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
      <div class="bar">
        <h2>Streams (TCP/UDP forward)</h2>
        <button onClick={() => setEdit({ ...empty })}>+ Add stream</button>
      </div>
      <Err msg={error()} />
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
          {paged.rows().map((r) => (
            <tr>
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
      <Pagination {...paged} />

      {edit() && (
        <Modal onClose={() => setEdit(null)}>
        <form class="editor" onSubmit={(e) => { e.preventDefault(); save() }}>
          <h3>{edit()!.id ? 'Edit stream' : 'New stream'}</h3>
          <Row label="Container port (>1024)">
            <input type="number" value={edit()!.port} onInput={(e) => setEdit({ ...edit()!, port: +e.currentTarget.value })} />
          </Row>
          <Row label="Backend (host:port)">
            <input value={edit()!.backend} onInput={(e) => setEdit({ ...edit()!, backend: e.currentTarget.value })} />
          </Row>
          <div class="checks">
            <Check label="UDP" checked={edit()!.udp} onChange={(v) => setEdit({ ...edit()!, udp: v })} />
            <Check label="Enabled" checked={edit()!.enabled} onChange={(v) => setEdit({ ...edit()!, enabled: v })} />
          </div>
          <div class="bar">
            <button type="submit" disabled={busy()}>Save & apply</button>
            <button type="button" onClick={() => setEdit(null)}>Cancel</button>
          </div>
        </form>
        </Modal>
      )}
    </section>
  )
}
