# super-nginx

Web UI quản lý nginx (proxy hosts, SSL/ACME, mail proxy, WAF) trên base image
[nginx-distroless](https://github.com/morningstar-sudo/nginx-distroless):
distroless, nonroot, readonly-rootfs, không shell. Toàn bộ backend + UI là
**một** Go static binary (`/usr/sbin/super-nginx`) thay entrypoint của base:
supervisor nginx + REST API + frontend embed.

Xem [PLAN.md](PLAN.md) — kiến trúc + lộ trình. Trạng thái: **Phase 0**
(supervisor + UI skeleton + health endpoint).

## Build & run

```sh
docker build -t super-nginx .
# local: dùng base tag local thay vì ghcr
docker build --build-arg BASE_IMAGE=nginx-distroless:stream-test -t super-nginx .

docker run --rm -p 8080:8080 -p 8181:8181 \
  --read-only --tmpfs /tmp -v super-nginx-data:/data super-nginx
```

- `:8080` — nginx (http; các listener khác do UI cấu hình sau)
- `:8181` — management UI + API (`/api/v1/health`)
- `/data` — volume duy nhất: DB, config render, certs, ACME state, backups
- `IS_MS_ON=true` — bật ModSecurity + CRS (default cho tới khi có per-host toggle)

## Dev

```sh
cd web && npm install && npm run build   # frontend → web/dist (go:embed cần dist tồn tại)
go build ./cmd/super-nginx               # linux binary build trong Docker; local build để check compile
cd web && npm run dev                    # Vite dev server, proxy /api → :8181
```
