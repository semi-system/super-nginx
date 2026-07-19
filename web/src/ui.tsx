import { useState, useEffect } from 'react'

// Tiny shared form helpers — no UI library.

// Modal: overlay + centered box. Backdrop click or Escape closes.
export function Modal({ onClose, children }: { onClose: () => void; children: any }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])
  return (
    <div className="modal-overlay" onMouseDown={onClose}>
      <div className="modal" onMouseDown={(e) => e.stopPropagation()}>
        {children}
      </div>
    </div>
  )
}

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
