# super-nginx

Web UI quản lý nginx (proxy hosts, SSL/ACME, mail proxy, WAF) trên base image
[nginx-distroless](https://github.com/morningstar-sudo/nginx-distroless):
distroless, nonroot, readonly-rootfs, không shell. Toàn bộ backend + UI là
**một** Go static binary (`/usr/sbin/super-nginx`) thay entrypoint của base:
supervisor nginx + REST API + frontend embed.

Xem [PLAN.md](PLAN.md) — kiến trúc + lộ trình. Trạng thái: **Phase 1–5 hoạt động**:

- Hosts: proxy / load balancer / redirect / static, HTTP/2, HSTS, websocket, force-SSL,
  load balancing round-robin / least-connections / IP hash, backend weight + passive failover
  và HTTP health probe chủ động (path/timeout, tự refresh trạng thái mỗi 30 giây),
  tùy chọn xác minh CA/hostname của HTTPS backend,
  custom nginx snippet (server + location), WAF ModSecurity+CRS **per-host**
- Pipeline an toàn: mọi thay đổi → render → `nginx -t` → reload; config hỏng
  bị từ chối kèm nguyên văn lỗi, tự rollback
- Certificates: upload custom (validate key/SAN/expiry), Let's Encrypt qua
  lego nhúng (HTTP-01 + DNS-01/wildcard, ~100 provider), auto-renew <30 ngày;
  tùy chọn isolate cấp một cert riêng cho từng domain trong cùng host để SAN
  không làm lộ các domain còn lại
- Mail proxy (stream): TLS terminate với SNI — mỗi domain một cert trên cùng
  port, dùng chung cert với HTTPS host; passthrough cho port plain/STARTTLS;
  auth ở backend
- Streams TCP/UDP forward
- Default site (`_`) cấu hình trong Settings: đóng kết nối (444, mặc định) /
  404 / redirect / trang HTML tự soạn — không còn lộ trang welcome của nginx;
  HTTPS với SNI lạ bị từ chối ngay ở bước bắt tay TLS
- Access lists: basic auth (htpasswd) + IP allow/deny, satisfy any/all, gắn per-host
- Backup/restore (tar.gz: state + certs + ACME account), audit log, metrics stub_status
- Auth: admin + password random in ra log lần đầu, session cookie/bearer

## Build & run

```sh
docker build -t super-nginx .
# local: dùng base tag local thay vì ghcr
docker build --build-arg BASE_IMAGE=nginx-distroless:stream-test -t super-nginx .

docker run --rm -p 80:8080 -p 443:8443 -p 8181:8181 \
  --read-only --tmpfs /tmp -v super-nginx-data:/data super-nginx
# mail/stream listener: mở thêm port tương ứng, ví dụ -p 465:2465
```

Hoặc dùng **docker compose** (bind mount `./data` để dữ liệu nằm trên host,
sống qua mọi lần recreate container):

```sh
docker compose up -d          # init service tự chown ./data cho uid 65532
```

- `:8080` / `:8443` — nginx http/https (map từ 80/443 ở host)
- `:8181` — management UI + API; password admin in ra log lần đầu chạy
- `/data` — volume duy nhất: state.json, config render, certs, ACME state.
  **Phải là named volume hoặc bind mount** — mất `/data` là mất toàn bộ cấu
  hình. Bind mount folder mới thì cần chown uid 65532 (compose làm sẵn qua
  init service; `docker run -v` thì dùng named volume để khỏi lo).
- WAF bật per-host trong UI (`IS_MS_ON=true` chỉ còn là default toàn cục)

## Dev

```sh
cd web && npm install && npm run build   # frontend → web/dist (go:embed cần dist tồn tại)
go build ./cmd/super-nginx               # linux binary build trong Docker; local build để check compile
cd web && npm run dev                    # Vite dev server, proxy /api → :8181
```
