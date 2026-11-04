import { createSignal, onMount } from 'solid-js'
import { get } from './api'
import { Err, Pagination, useAsync, usePaged } from './ui'

export default function ConfigView() {
  const [files, setFiles] = createSignal<Record<string, string>>({})
  const { error, run } = useAsync()
  const paged = usePaged(() => Object.entries(files()))

  onMount(() => {
    run(async () => setFiles(await get('/api/v1/nginx/config')))
  })

  return (
    <section>
      <h2>Rendered nginx config</h2>
      <p class="hint">Read-only — generated from the database on every change, validated with nginx -t before reload.</p>
      <Err msg={error()} />
      {paged.rows().map(([name, content]) => (
        <details open>
          <summary>{name}</summary>
          <pre>{content}</pre>
        </details>
      ))}
      <Pagination {...paged} />
    </section>
  )
}
