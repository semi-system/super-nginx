import { useState, KeyboardEvent, ClipboardEvent } from 'react'

// NPM-style tag input: type a domain, Enter/space/comma turns it into a chip.
// Backspace on an empty field removes the last chip.
const DOMAIN_RE = /^(\*\.)?([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$|^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/i

export default function DomainInput({
  value,
  onChange,
  placeholder = 'example.com',
}: {
  value: string[]
  onChange: (v: string[]) => void
  placeholder?: string
}) {
  const [draft, setDraft] = useState('')

  const add = (raw: string) => {
    const parts = raw.split(/[\s,]+/).map((s) => s.trim().toLowerCase()).filter(Boolean)
    const next = [...value]
    for (const p of parts) if (!next.includes(p)) next.push(p)
    onChange(next)
  }

  const commitDraft = () => {
    if (draft.trim()) add(draft)
    setDraft('')
  }

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' || e.key === ',' || e.key === ' ') {
      e.preventDefault()
      commitDraft()
    } else if (e.key === 'Backspace' && !draft && value.length) {
      onChange(value.slice(0, -1))
    }
  }

  const onPaste = (e: ClipboardEvent<HTMLInputElement>) => {
    e.preventDefault()
    add(e.clipboardData.getData('text'))
    setDraft('')
  }

  return (
    <div className="tags" onClick={(e) => (e.currentTarget.querySelector('input') as HTMLInputElement)?.focus()}>
      {value.map((d) => (
        <span key={d} className={'tag' + (DOMAIN_RE.test(d) ? '' : ' tag-bad')}>
          {d}
          <button type="button" onClick={() => onChange(value.filter((x) => x !== d))}>
            ✕
          </button>
        </span>
      ))}
      <input
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        onKeyDown={onKeyDown}
        onPaste={onPaste}
        onBlur={commitDraft}
        placeholder={value.length ? '' : placeholder}
      />
    </div>
  )
}
