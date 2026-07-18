import { useEffect, useState } from 'react'

type Health = { status: string; nginx: { running: boolean } }

export default function App() {
  const [health, setHealth] = useState<Health | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetch('/api/v1/health')
      .then((r) => r.json())
      .then(setHealth)
      .catch((e) => setError(String(e)))
  }, [])

  return (
    <main style={{ fontFamily: 'system-ui', margin: '4rem auto', maxWidth: 640 }}>
      <h1>super-nginx</h1>
      {error && <p style={{ color: 'crimson' }}>API error: {error}</p>}
      {health && (
        <p>
          nginx: <strong>{health.nginx.running ? 'running' : 'stopped'}</strong>
        </p>
      )}
    </main>
  )
}
