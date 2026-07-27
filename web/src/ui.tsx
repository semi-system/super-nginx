import { useState, useEffect, useMemo } from 'react'
import { pageCount, clampPage, pageSlice, pageWindow } from './paging'

// Tiny shared form helpers — no UI library, just the S!mple design system classes.

// Modal: overlay + centered box. Backdrop click or Escape closes.
export function Modal({ onClose, children }: { onClose: () => void; children: any }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])
  return (
    <div className="modal-backdrop open" onMouseDown={onClose}>
      <div className="modal modal-lg" onMouseDown={(e) => e.stopPropagation()}>
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

// Client-side paging for a list already held in memory.
export function usePaged<T>(items: T[], size = 10) {
  const [page, setPage] = useState(1)
  const pages = pageCount(items.length, size)
  const current = clampPage(page, pages)
  const rows = useMemo(() => pageSlice(items, current, size), [items, current, size])
  return { rows, page: current, pages, setPage, total: items.length, size }
}

type Paged = ReturnType<typeof usePaged<any>>

// Row count + page buttons. Renders nothing while everything fits on one page.
export function Pagination({ page, pages, setPage, total, size }: Paged) {
  if (pages < 2) return null
  const from = (page - 1) * size + 1
  return (
    <div className="pager">
      <span className="pager-info">
        {from}–{Math.min(page * size, total)} of {total}
      </span>
      <div className="pagination">
        <button onClick={() => setPage(page - 1)} disabled={page === 1} aria-label="Previous page">
          ‹
        </button>
        {pageWindow(page, pages).map((p, i) =>
          p === '…' ? (
            <span key={`gap${i}`} className="ellipsis">
              …
            </span>
          ) : (
            <button
              key={p}
              className={p === page ? 'active' : ''}
              aria-current={p === page ? 'page' : undefined}
              onClick={() => setPage(p)}
            >
              {p}
            </button>
          ),
        )}
        <button onClick={() => setPage(page + 1)} disabled={page === pages} aria-label="Next page">
          ›
        </button>
      </div>
    </div>
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
