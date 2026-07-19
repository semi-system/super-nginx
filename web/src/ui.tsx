import { useState } from 'react'

// Tiny shared form helpers — no UI library.

export function Err({ msg }: { msg: string | null }) {
  if (!msg) return null
  return <p className="error">{msg}</p>
}

export function Row({ label, children }: { label: string; children: any }) {
  return (
    <label className="row">
      <span>{label}</span>
      {children}
    </label>
  )
}

export function Check({
  label,
  checked,
  onChange,
}: {
  label: string
  checked: boolean
  onChange: (v: boolean) => void
}) {
  return (
    <label className="check">
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} />
      {label}
    </label>
  )
}

export function useAsync() {
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const run = async (fn: () => Promise<void>) => {
    setBusy(true)
    setError(null)
    try {
      await fn()
    } catch (e: any) {
      setError(e.message || String(e))
    } finally {
      setBusy(false)
    }
  }
  return { error, busy, run, setError }
}
