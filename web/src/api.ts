export async function api<T = any>(path: string, opts: RequestInit = {}): Promise<T> {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    ...opts,
  })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(data.error || res.statusText)
  return data as T
}
export const get = <T = any>(p: string) => api<T>(p)
export const post = <T = any>(p: string, body?: any) =>
  api<T>(p, { method: 'POST', body: JSON.stringify(body ?? {}) })
export const put = <T = any>(p: string, body: any) =>
  api<T>(p, { method: 'PUT', body: JSON.stringify(body) })
export const del = <T = any>(p: string) => api<T>(p, { method: 'DELETE' })

export type Host = {
  id: number
  type: 'proxy' | 'load_balancer' | 'redirect' | 'static'
  domains: string[]
  target: string
  upstream_scheme: 'http' | 'https'
  load_balance: 'round_robin' | 'least_conn' | 'ip_hash'
  upstreams: Upstream[]
  cert_id: number
  isolate_certs: boolean
  domain_certs: Record<string, number>
  force_ssl: boolean
  http2: boolean
  hsts: boolean
  websocket: boolean
  waf: boolean
  access_list_id: number
  cache: boolean
  cache_time: string
  directives: { key: string; value: string }[]
  server_snippet: string
  location_snippet: string
  enabled: boolean
}

export type Upstream = {
  address: string
  weight: number
  max_fails: number
  fail_timeout: string
  backup: boolean
}

export type Cert = {
  id: number
  name: string
  type: 'custom' | 'acme'
  domains: string[]
  challenge?: string
  dns_provider?: string
  expires_at: string
  last_error?: string
}

export type MailListener = {
  id: number
  label: string
  port: number
  mode: 'terminate' | 'passthrough'
  default_backend: string
  proxy_ssl: boolean
  enabled: boolean
}

export type MailDomain = {
  id: number
  domain: string
  cert_id: number
}

export type StreamRule = {
  id: number
  port: number
  udp: boolean
  backend: string
  enabled: boolean
}
