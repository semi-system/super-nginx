import { createSignal, onMount } from 'solid-js'
import { get, post, put, del } from './api'
import { Err, Row, Modal, Pagination, useAsync, usePaged } from './ui'

type ListOut = {
  id: number
  name: string
  satisfy: string
  users: string[] | null
  allow: string[] | null
  deny: string[] | null
}

type EditState = {
  id: number
  name: string
  satisfy: string
  users: { username: string; password: string }[]
  allow: string
  deny: string
}

const empty: EditState = { id: 0, name: '', satisfy: 'all', users: [], allow: '', deny: '' }

export default function Access() {
  const [lists, setLists] = createSignal<ListOut[]>([])
  const [edit, setEdit] = createSignal<EditState | null>(null)
  const { error, busy, run } = useAsync()
  const paged = usePaged(lists)

  const reload = async () => setLists((await get('/api/v1/accesslists')) ?? [])
  onMount(() => {
    run(reload)
  })

  const save = () =>
    run(async () => {
      const current = edit()
      if (!current) return
      const body = {
        name: current.name,
        satisfy: current.satisfy,
        users: current.users.filter((u) => u.username),
        allow: current.allow.split(/\s+/).filter(Boolean),
        deny: current.deny.split(/\s+/).filter(Boolean),
      }
      if (current.id === 0) await post('/api/v1/accesslists', body)
      else await put(`/api/v1/accesslists/${current.id}`, body)
      setEdit(null)
      await reload()
    })

  const remove = (id: number) =>
    run(async () => {
      if (!confirm('Delete access list?')) return
      await del(`/api/v1/accesslists/${id}`)
      await reload()
    })

  const startEdit = (l: ListOut) =>
    setEdit({
      id: l.id,
      name: l.name,
      satisfy: l.satisfy || 'all',
      users: (l.users || []).map((u) => ({ username: u, password: '' })),
      allow: (l.allow || []).join('\n'),
      deny: (l.deny || []).join('\n'),
    })

  return (
    <section>
      <div class="bar">
        <h2>Access lists</h2>
        <button onClick={() => setEdit({ ...empty, users: [] })}>+ Add list</button>
      </div>
      <p class="hint">Basic auth users and/or IP allow/deny, attached to hosts in the host editor.</p>
      <Err msg={error()} />
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Users</th>
            <th>Allow</th>
            <th>Deny</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {paged.rows().map((l) => (
            <tr>
              <td>{l.name}</td>
              <td>{(l.users || []).join(', ') || '—'}</td>
              <td>{(l.allow || []).join(', ') || '—'}</td>
              <td>{(l.deny || []).join(', ') || '—'}</td>
              <td>
                <button onClick={() => startEdit(l)}>Edit</button>{' '}
                <button onClick={() => remove(l.id)}>Delete</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <Pagination {...paged} />

      {edit() && (
        <Modal onClose={() => setEdit(null)}>
        <form class="editor" onSubmit={(e) => { e.preventDefault(); save() }}>
          <h3>{edit()!.id ? 'Edit access list' : 'New access list'}</h3>
          <Row label="Name">
            <input value={edit()!.name} onInput={(e) => setEdit({ ...edit()!, name: e.currentTarget.value })} />
          </Row>
          <Row label="Satisfy (when both users and IP rules present)">
            <select value={edit()!.satisfy} onChange={(e) => setEdit({ ...edit()!, satisfy: e.currentTarget.value })}>
              <option value="all">all — must pass auth AND ip rules</option>
              <option value="any">any — either is enough</option>
            </select>
          </Row>
          <Row label="Users (leave password blank to keep existing)">
            <div>
              {edit()!.users.map((u, i) => (
                <div style={{ display: 'flex', gap: '6px', 'margin-bottom': '6px' }}>
                  <input
                    placeholder="username"
                    value={u.username}
                    onChange={(e) => {
                      const users = [...edit()!.users]
                      users[i] = { ...u, username: e.target.value }
                      setEdit({ ...edit()!, users })
                    }}
                  />
                  <input
                    placeholder="password"
                    type="password"
                    value={u.password}
                    onChange={(e) => {
                      const users = [...edit()!.users]
                      users[i] = { ...u, password: e.target.value }
                      setEdit({ ...edit()!, users })
                    }}
                  />
                  <button type="button" onClick={() => setEdit({ ...edit()!, users: edit()!.users.filter((_, j) => j !== i) })}>
                    ✕
                  </button>
                </div>
              ))}
              <button type="button" onClick={() => setEdit({ ...edit()!, users: [...edit()!.users, { username: '', password: '' }] })}>
                + user
              </button>
            </div>
          </Row>
          <Row label="Allow (IP/CIDR, one per line — implies deny all others)">
            <textarea rows={3} value={edit()!.allow} onInput={(e) => setEdit({ ...edit()!, allow: e.currentTarget.value })} placeholder="10.0.0.0/8" />
          </Row>
          <Row label="Deny (IP/CIDR, one per line)">
            <textarea rows={2} value={edit()!.deny} onInput={(e) => setEdit({ ...edit()!, deny: e.currentTarget.value })} />
          </Row>
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
