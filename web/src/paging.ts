// Pure pagination math — kept out of the component so it can be tested with
// plain node (see paging.test.mjs).

export const pageCount = (total: number, size: number) => Math.max(1, Math.ceil(total / size))

// Page is clamped: the list can shrink under a page that is no longer there.
export const clampPage = (page: number, pages: number) => Math.min(Math.max(1, page), pages)

export function pageSlice<T>(items: T[], page: number, size: number): T[] {
  const start = (clampPage(page, pageCount(items.length, size)) - 1) * size
  return items.slice(start, start + size)
}

// Page numbers to render, with '…' where a run is skipped.
// span = how many neighbours around the current page to keep.
export function pageWindow(page: number, pages: number, span = 1): (number | '…')[] {
  const keep = new Set([1, pages])
  for (let p = page - span; p <= page + span; p++) if (p >= 1 && p <= pages) keep.add(p)
  const out: (number | '…')[] = []
  let prev = 0
  for (const p of [...keep].sort((a, b) => a - b)) {
    if (prev && p - prev > 1) out.push('…')
    out.push(p)
    prev = p
  }
  return out
}
