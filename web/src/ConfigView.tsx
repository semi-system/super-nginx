import { useEffect, useState } from 'react'
import { get } from './api'
import { Err, useAsync } from './ui'

export default function ConfigView() {
  const [files, setFiles] = useState<Record<string, string>>({})
  const { error, run } = useAsync()

  useEffect(() => {
    run(async () => setFiles(await get('/api/v1/nginx/config')))
  }, [])

  return (
    <section>
      <h2>Rendered nginx config</h2>
      <p className="hint">Read-only — generated from the database on every change, validated with nginx -t before reload.</p>
      <Err msg={error} />
      {Object.entries(files).map(([name, content]) => (
        <details key={name} open>
          <summary>{name}</summary>
          <pre>{content}</pre>
        </details>
      ))}
    </section>
  )
}
