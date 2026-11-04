import { createSignal, JSX } from 'solid-js'

const DOMAIN_RE = /^(\*\.)?([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$|^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/i

export default function DomainInput(props: {
  value: string[]
  onChange: (value: string[]) => void
  placeholder?: string
}) {
  const [draft, setDraft] = createSignal('')

  const add = (raw: string) => {
    const next = [...props.value]
    for (const domain of raw.split(/[\s,]+/).map((item) => item.trim().toLowerCase()).filter(Boolean)) {
      if (!next.includes(domain)) next.push(domain)
    }
    props.onChange(next)
  }

  const commitDraft = () => {
    if (draft().trim()) add(draft())
    setDraft('')
  }

  const onKeyDown: JSX.EventHandler<HTMLInputElement, KeyboardEvent> = (event) => {
    if (event.key === 'Enter' || event.key === ',' || event.key === ' ') {
      event.preventDefault()
      commitDraft()
    } else if (event.key === 'Backspace' && !draft() && props.value.length) {
      props.onChange(props.value.slice(0, -1))
    }
  }

  const onPaste: JSX.EventHandler<HTMLInputElement, ClipboardEvent> = (event) => {
    event.preventDefault()
    add(event.clipboardData?.getData('text') ?? '')
    setDraft('')
  }

  return (
    <div class="tags picker-control" onClick={(event) => event.currentTarget.querySelector('input')?.focus()}>
      {props.value.map((domain) => (
        <span class={`tag${DOMAIN_RE.test(domain) ? '' : ' tag-bad'}`}>
          {domain}
          <button type="button" aria-label={`Remove ${domain}`} onClick={() => props.onChange(props.value.filter((item) => item !== domain))}>×</button>
        </span>
      ))}
      <input
        value={draft()}
        onInput={(event) => setDraft(event.currentTarget.value)}
        onKeyDown={onKeyDown}
        onPaste={onPaste}
        onBlur={commitDraft}
        placeholder={props.value.length ? '' : (props.placeholder ?? 'example.com')}
      />
    </div>
  )
}
