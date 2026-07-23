# syntax=docker/dockerfile:1
# Local build against a local base tag:
#   docker build --build-arg BASE_IMAGE=nginx-distroless:stream-test -t super-nginx .
ARG BASE_IMAGE=ghcr.io/morningstar-sudo/nginx-distroless:latest

FROM node:22-alpine AS frontend
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.26-alpine AS backend
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /web/dist ./web/dist
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /super-nginx ./cmd/super-nginx
# /data skeleton: named volumes copy this up on first mount, keeping uid 65532
# ownership so the nonroot runtime can write (distroless final stage can't RUN mkdir)
RUN mkdir -p /data-skel

FROM ${BASE_IMAGE}
COPY --from=backend /super-nginx /usr/sbin/super-nginx
COPY --from=backend --chown=65532:65532 /data-skel /data
COPY bridge/conf.d/ /etc/nginx/conf.d/
COPY bridge/mail.d/ /etc/nginx/mail.d/
COPY bridge/stream.d/ /etc/nginx/stream.d/

EXPOSE 8080 8181 8443
ENTRYPOINT ["/usr/sbin/super-nginx"]
