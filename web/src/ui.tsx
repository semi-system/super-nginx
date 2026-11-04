import { Accessor, createMemo, createSignal, JSX, onCleanup, onMount } from 'solid-js'
import { pageCount, clampPage, pageSlice, pageWindow } from './paging'

// Shared primitives keep modal, field, checkbox, async, and paging behaviour
// consistent across every section of the control panel.
export function Modal(props: { onClose: () => void; children: JSX.Element }) {
  onMount(() => {
    const onKey = (event: KeyboardEvent) => event.key === 'Escape' && props.onClose()
    window.addEventListener('keydown', onKey)
    onCleanup(() => window.removeEventListener('keydown', onKey))
  })

  return (
    <div class="modal-backdrop open" onMouseDown={props.onClose}>
      <div class="modal modal-lg" onMouseDown={(event) => event.stopPropagation()} role="dialog" aria-modal="true">
        {props.children}
      </div>
    </div>
  )
}

export function Err(props: { msg: string | null }) {
  return <>{props.msg && <p class="alert alert-danger">{props.msg}</p>}</>
}

export function Row(props: { label: string; hint?: string; children: JSX.Element }) {
  return (
    <label class="row">
      <span>{props.label}</span>
      {props.children}
      {props.hint && <small class="field-hint">{props.hint}</small>}
    </label>
  )
}

export function Check(props: { label: string; checked: boolean; onChange: (value: boolean) => void }) {
  return (
    <label class="check">
      <input type="checkbox" checked={props.checked} onChange={(event) => props.onChange(event.currentTarget.checked)} />
      <span>{props.label}</span>
    </label>
  )
}

export function usePaged<T>(items: Accessor<T[]>, size = 10) {
  const [requestedPage, setPage] = createSignal(1)
  const pages = createMemo(() => pageCount(items().length, size))
  const page = createMemo(() => clampPage(requestedPage(), pages()))
  const rows = createMemo(() => pageSlice(items(), page(), size))
  return { rows, page, pages, setPage, total: () => items().length, size }
}

type Paged = ReturnType<typeof usePaged<any>>

export function Pagination(props: Paged) {
  const from = () => (props.page() - 1) * props.size + 1
  return (
    <div class="pager" style={{ display: props.pages() < 2 ? 'none' : undefined }}>
      <span class="pager-info">
        {from()}–{Math.min(props.page() * props.size, props.total())} of {props.total()}
      </span>
      <div class="pagination">
        <button onClick={() => props.setPage(props.page() - 1)} disabled={props.page() === 1} aria-label="Previous page">‹</button>
        {pageWindow(props.page(), props.pages()).map((item) =>
          item === '…' ? (
            <span class="ellipsis" aria-hidden="true">…</span>
          ) : (
            <button
              class={item === props.page() ? 'active' : ''}
              aria-current={item === props.page() ? 'page' : undefined}
              onClick={() => props.setPage(item)}
            >
              {item}
            </button>
          ),
        )}
        <button onClick={() => props.setPage(props.page() + 1)} disabled={props.page() === props.pages()} aria-label="Next page">›</button>
      </div>
    </div>
  )
}

export function useAsync() {
  const [error, setError] = createSignal<string | null>(null)
  const [busy, setBusy] = createSignal(false)

  const run = async <T,>(task: () => Promise<T>) => {
    setBusy(true)
    setError(null)
    try {
      await task()
    } catch (cause: any) {
      setError(cause?.message || String(cause))
    } finally {
      setBusy(false)
    }
  }

  return { error, busy, run, setError }
}
