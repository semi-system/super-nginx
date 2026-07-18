# super-nginx — Kế hoạch triển khai

Quản lý toàn bộ nginx qua Web UI (kiểu Nginx Proxy Manager + NGINX UI), chạy trên
base image `nginx-distroless` (nginx static + ModSecurity v3, distroless,
nonroot 65532, readonly-rootfs, không shell).

---

## 1. Kiến trúc tổng thể

**Một image duy nhất, một binary Go duy nhất.**

```
FROM ghcr.io/<owner>/nginx-distroless:latest
COPY super-nginx /usr/sbin/super-nginx     # Go static binary, embed toàn bộ UI
ENTRYPOINT ["/usr/sbin/super-nginx"]
```

`super-nginx` (Go) thay thế `/entrypoint` của base và đảm nhiệm:

1. **Supervisor**: spawn nginx làm child process → gửi được `SIGHUP` (reload),
   `SIGQUIT` (graceful stop) trực tiếp, không cần docker.sock hay shared PID
   namespace. Nginx chết → supervisor restart (backoff) hoặc exit để orchestrator lo.
2. **Config engine**: DB (SQLite) là source of truth → render ra file nginx conf
   → `nginx -t` → apply → `SIGHUP`. Test fail → rollback, không bao giờ đẩy
   config hỏng vào nginx đang chạy.
3. **REST API + Web UI**: embed frontend bằng `go:embed`, serve trên port riêng
   (mặc định `81 → 8181` vì nonroot không bind <1024).
4. **ACME client**: thư viện `go-acme/lego` in-process (không cần certbot,
   không shell — bắt buộc vì distroless).
5. **Scheduler**: cron in-process cho auto-renew cert, log rotation, backup.
6. **Mail/TCP proxy qua stream module** — không xác thực tại proxy, auth ở
   backend (mục 5).

**Lý do chọn 1 binary trong 1 container** thay vì sidecar 2 container:
distroless không có shell/exec, sidecar không gửi được signal cho nginx nếu
không mount docker.sock (lỗ hổng an ninh) hoặc shared PID namespace (phức tạp,
không chạy được với `docker run` đơn lẻ). Go static binary chạy thẳng trên
`chainguard/static`, giữ nguyên mọi tính chất của base (readonly, nonroot, no shell).

### Stack

| Thành phần | Chọn | Lý do |
|---|---|---|
| Backend | Go 1.2x, static build (`CGO_ENABLED=0`) | chạy trên distroless, 1 binary |
| DB | SQLite qua `modernc.org/sqlite` | pure Go (không CGO), 1 file trong volume |
| ACME | `go-acme/lego` (library mode) | HTTP-01 + DNS-01, không cần binary ngoài |
| HTTP router | `net/http` + `chi` | đủ dùng, không framework nặng |
| Frontend | Vite + React + TypeScript, build ra static, `go:embed` | giống nginx-ui/NPM, không runtime node |
| Template conf | Go `text/template` | render nginx conf từ model |

### Layout dữ liệu (volume duy nhất `/data`)

```
/data/
  db/super-nginx.db          # SQLite
  nginx/
    conf.d/*.conf            # server blocks render ra (http)
    stream.d/*.conf          # stream{} render ra (mail proxy + TCP/UDP forward)
  certs/<cert_id>/fullchain.pem, privkey.pem
  acme/                      # account key, trạng thái lego
  backups/                   # export định kỳ
  logs/                      # access/error log per-host (tùy chọn)
```

Base image include sẵn `/etc/nginx/conf.d/*.conf`, `mail.d/*.conf`,
`stream.d/*.conf`. super-nginx COPY các file mồi (bridge) vào đó chỉ chứa
`include /data/nginx/<tên>.d/*.conf;` → **không sửa base image**, đúng triết lý
"copy in, never modify".

Container chạy: `--read-only --tmpfs /tmp -v super-nginx-data:/data`.

---

## 2. Config engine (lõi của toàn dự án — làm đầu tiên)

Mọi feature (host, cert, mail, WAF) đều đi qua một pipeline duy nhất:

```
DB model → render template ra thư mục staging (/tmp/render-<n>/)
        → nginx -t với config trỏ staging
        → OK: atomic swap vào /data/nginx/, SIGHUP
        → FAIL: giữ nguyên config cũ, trả lỗi nginx -t về UI (hiển thị nguyên văn)
```

Quy tắc:
- Không bao giờ cho user sửa file trực tiếp làm source of truth — DB là gốc,
  file chỉ là artifact render. (Có "Advanced/Custom config" per-host dưới dạng
  snippet inject vào template — đáp ứng yêu cầu *inline rule*.)
- Mỗi lần apply ghi 1 bản snapshot config + version vào DB → nút rollback trên UI.
- `nginx -t` chạy được dưới nonroot vì base đã trỏ pid/temp path vào `/tmp`.

**Inline rule (custom directives)** — 3 mức, đều validate qua `nginx -t`:
1. Per-location snippet (dán directive vào trong `location`)
2. Per-server snippet (trong `server {}`)
3. Global http snippet (file riêng trong conf.d)

---

## 3. Quản lý host (tính năng kiểu NPM)

- **Proxy host**: domain(s) → upstream (scheme/host/port), websocket upgrade,
  headers chuẩn (`X-Real-IP`, `X-Forwarded-*`), HTTP/2, HSTS, force-SSL
  redirect, custom locations, per-host access/error log.
- **Redirect host**: 301/302 sang domain khác, giữ path hay không.
- **Static host**: serve từ thư mục trong `/data` (dùng root nginx sẵn có).
- **404/default host**: server block `default_server` catch-all.
- **Access list**: basic auth (htpasswd do backend generate) + allow/deny CIDR.
- **WAF per-host**: vì ModSecurity compile tĩnh, thêm toggle
  `modsecurity on; modsecurity_rules_file ...` **per server block** thay vì
  toàn cục qua `IS_MS_ON` → hơn hẳn base image. UI thêm được
  `SecRuleRemoveById` per-host (CRS exclusions). `IS_MS_ON` vẫn được tôn trọng
  làm default cho host mới.

Lưu ý port: trong container listen `8080` (http) / `8443` (https); mapping
`80:8080`, `443:8443` ở host/LB. UI hiển thị rõ điều này.

---

## 4. SSL / Certificates

### 4.1 Model

Bảng `certificates`:
- `type`: `acme` | `custom`
- `domains`: danh sách SAN (nhiều domain / wildcard trên 1 cert)
- `status`, `expires_at`, `last_renewal`, provider info

Host và mail server **tham chiếu** cert theo id → 1 cert dùng chung cho nhiều
host + mail (yêu cầu "dùng chung với https" — xem 5).

### 4.2 ACME (Let's Encrypt / ZeroSSL, lego)

- **HTTP-01**: super-nginx render sẵn location
  `/.well-known/acme-challenge/` proxy về chính nó trong *mọi* server block
  port 8080 → issue không downtime. Yêu cầu host map port 80 → 8080.
- **DNS-01**: cho wildcard; lego có sẵn provider (Cloudflare, Route53,
  DuckDNS…). UI: chọn provider + nhập credentials (lưu mã hoá trong DB).
- **Auto-renew**: scheduler check mỗi 12h, renew khi còn <30 ngày, sau renew
  → ghi cert ra `/data/certs/<id>/` → `nginx -t` → `SIGHUP`. Renew fail →
  giữ cert cũ, đánh dấu trạng thái lỗi trên UI (+ tùy chọn webhook/email cảnh báo).
- ACME account key + trạng thái lưu `/data/acme/`.

### 4.3 Custom cert

- Upload fullchain + private key (paste hoặc file), backend validate:
  parse được, key khớp cert, chain hợp lệ, cảnh báo hết hạn.
- Hiển thị SAN list, issuer, expiry; nhắc hết hạn trên dashboard.

---

## 5. Mail proxy (multi-domain, SSL/TLS, dùng chung cert với HTTPS)

**Quyết định**: proxy mail **không xác thực** — auth hoàn toàn ở backend mail
server. Vì vậy **không dùng `mail{}` module** (mail module bắt buộc `auth_http`
và can thiệp protocol). Dùng **`stream{}` module** (đã thêm vào base): proxy
TCP thuần, chỉ terminate TLS hoặc passthrough. Render vào
`/data/nginx/stream.d/`.

### 5.1 Hai chế độ per-listener

1. **TLS terminate** (implicit TLS: SMTPS 465, IMAPS 993, POP3S 995 — trong
   container listen >1024, ví dụ 2465/2993/2995):
   - `listen <port> ssl;` + cert do super-nginx quản lý.
   - **SNI hoạt động** (khác mail module): `$ssl_server_name` + cert theo biến
     (stream hỗ trợ từ nginx 1.31, base đang build 1.31.3) → nhiều domain,
     **mỗi domain cert riêng trên cùng port**, hoặc dùng chung cert
     SAN/wildcard với HTTPS host (cùng `cert_id`, renew 1 lần cả web + mail).
   - Route backend theo SNI: `map $ssl_server_name → upstream`.
   - Sau terminate → `proxy_pass` plain tới backend.
2. **Passthrough** (port plain 25/143/110 hoặc muốn backend tự cầm TLS):
   - Forward TCP nguyên vẹn, tùy chọn `ssl_preread` để route theo SNI mà không
     giải mã.
   - **Giới hạn ghi rõ trong UI**: STARTTLS trên port plain không terminate
     được ở proxy (STARTTLS nằm trong protocol, stream không parse) → cert cho
     STARTTLS phải nằm ở backend. Client hiện đại dùng implicit TLS nên
     terminate mode phủ phần lớn nhu cầu.

### 5.2 Model & render

Bảng `mail_listeners`:
- listen port trong container (>1024) + nhãn protocol (smtp/imap/pop3 — chỉ để
  hiển thị, stream không phân biệt)
- mode: `terminate` | `passthrough`
- default backend (host:port) — dùng khi client không gửi SNI

Bảng `mail_domains`: domain → backend (host:port) + `cert_id` (mode terminate).
UI validate: domain thuộc SAN của cert được gán; cert có thể là cert đang dùng
cho HTTPS host (tham chiếu chung, không copy).

---

## 6. UI / API

### Màn hình
1. **Dashboard**: trạng thái nginx (running/uptime/version), cert sắp hết hạn,
   host count, lỗi renew, requests (parse stub_status).
2. **Hosts**: list + CRUD proxy/redirect/static/404, toggle SSL, WAF, custom snippet (code editor có syntax highlight nginx).
3. **Certificates**: list (domains, type, expiry, status), issue ACME, upload custom, renew now, xem host/mail nào đang dùng.
4. **Mail**: listeners + domain routing table + cert gắn kèm.
5. **Security**: WAF global default, CRS rule exclusions, audit log ModSecurity (đọc từ log).
6. **Config viewer**: xem config render ra (read-only) + diff giữa các version + rollback.
7. **Settings**: users (bcrypt/argon2), backup/restore (tar `/data` trừ logs), DNS providers, token API.

### API
- REST JSON `/api/v1/...`, session cookie cho UI + bearer token cho automation.
- Auth: user/pass → session; force đổi mật khẩu mặc định lần đầu (tránh vết xe đổ `admin@example.com/changeme` của NPM).
- Audit log mọi thay đổi config.

---

## 7. Thay đổi ở base image (nginx-distroless) — ĐÃ XONG (commit 871433d)

Đã thêm `--with-http_v2_module`, `--with-http_stub_status_module`,
`--with-stream`, `--with-stream_ssl_module` + extension point `stream.d/`
(stream module giờ là nền của mail proxy — mục 5 — và Streams TCP/UDP).
Không cần đổi gì thêm: entrypoint cũ bị super-nginx thay, extension points
(conf.d/mail.d/stream.d/modsecurity.d) dùng đúng như thiết kế.

---

## 8. Lộ trình (mỗi phase chạy được và có giá trị độc lập)

| Phase | Nội dung | Kết quả kiểm chứng |
|---|---|---|
| **0. Chuẩn bị** | Sửa base image (7.2, quyết 7.1); scaffold repo Go + Vite; Dockerfile 2-stage (build Go+FE → FROM nginx-distroless) | Image chạy, UI "hello" trên 8181, nginx serve 8080 |
| **1. Core engine** | Supervisor (spawn/reload/restart nginx), SQLite schema + migration, pipeline render→test→apply→rollback, auth user, REST khung | Tạo proxy host qua API → nginx reload → curl thấy proxy hoạt động; config hỏng bị chặn kèm lỗi `nginx -t` |
| **2. Hosts UI** | CRUD proxy/redirect/static/404, custom snippets 3 mức, access list, config viewer + diff + rollback | Thao tác toàn bộ qua UI, không cần sờ file |
| **3. SSL** | Custom cert upload + validate; lego HTTP-01; auto-renew scheduler; dashboard expiry | Issue cert thật (staging LE) qua UI, renew tự động, force-SSL hoạt động |
| **4. DNS-01 + wildcard** | Provider credentials (mã hoá), wildcard cert | Wildcard cert issue qua Cloudflare token |
| **5. Mail** | stream{} render: TLS terminate (SNI cert + route theo domain) và passthrough, cert dùng chung với https, validate SAN | SMTPS/IMAPS qua proxy với 2 domain + 2 cert khác nhau trên 1 listener; passthrough port plain |
| **6. WAF & security** | Per-host ModSecurity toggle, CRS exclusion UI, ModSec audit log viewer | Bật WAF cho 1 host, `?q=<script>` bị 403, host khác không ảnh hưởng |
| **7. Vận hành** | Backup/restore, API token, audit log, metrics stub_status, CI (build → Trivy strict → ghcr, giống base) | Restore ra container mới giữ nguyên trạng thái |

Thứ tự cứng: **Phase 1 là nền của tất cả** — mọi phase sau chỉ là model +
template + màn hình cắm vào pipeline đó.

---

## 9. Rủi ro & đối sách

| Rủi ro | Đối sách |
|---|---|
| STARTTLS trên port plain không terminate được ở stream proxy | UI ghi rõ: port plain = passthrough, cert STARTTLS nằm ở backend; hướng user dùng implicit TLS (465/993/995) |
| Distroless không shell → khó debug trong container | Mọi lỗi (nginx -t, ACME, render) trả nguyên văn về UI/log stdout; thêm endpoint `/api/v1/debug/state` |
| ACME HTTP-01 cần port 80 công khai | Docs + UI cảnh báo khi issue fail vì unreachable; có sẵn DNS-01 làm đường vòng |
| Renew xong nginx reload fail | Pipeline chung: test trước, fail thì giữ cert/config cũ + báo UI |
| SQLite corrupt / volume mất | Backup định kỳ vào `/data/backups` + nút export; WAL mode |
| Secrets (DNS token) trong DB | Mã hoá bằng key sinh lần đầu lưu `/data` (đủ cho v1; KMS là YAGNI) |
| Readonly rootfs | Toàn bộ ghi vào `/data` + `/tmp`; CI test với `--read-only` |

---

## 10. Ngoài phạm vi v1 (ghi lại để khỏi tranh cãi sau)

- Cluster / multi-node sync
- LDAP/OAuth cho UI login
- Xác thực mail tại proxy (mail module + auth_http) — auth luôn ở backend
- Quản lý nhiều instance nginx từ 1 UI
- Metrics Prometheus (chỉ stub_status ở v1)
