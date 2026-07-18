// Package web embeds the built frontend (web/dist). Run `npm run build` in
// web/ before `go build` — the Dockerfile does this automatically.
package web

import "embed"

//go:embed all:dist
var Dist embed.FS
