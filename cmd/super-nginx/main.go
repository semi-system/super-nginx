// Command super-nginx supervises the bundled nginx and serves the management
// UI/API: state in /data/db/state.json -> rendered nginx config -> nginx -t
// -> reload, with automatic rollback on failure.
package main

import (
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/morningstar-sudo/super-nginx/internal/api"
	"github.com/morningstar-sudo/super-nginx/internal/certs"
	"github.com/morningstar-sudo/super-nginx/internal/engine"
	"github.com/morningstar-sudo/super-nginx/internal/store"
	"github.com/morningstar-sudo/super-nginx/internal/supervisor"
	"github.com/morningstar-sudo/super-nginx/web"
)

var dataDirs = []string{
	"/data/nginx/conf.d",
	"/data/nginx/mail.d",
	"/data/nginx/stream.d",
	"/data/certs",
	"/data/db",
	"/data/logs",
	"/data/www",
	"/data/acme",
}

func confPath() string {
	if os.Getenv("IS_MS_ON") == "true" {
		return "/etc/nginx/nginx-ms.conf"
	}
	return "/etc/nginx/nginx.conf"
}

func main() {
	log.SetFlags(0)

	for _, d := range dataDirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			log.Printf("warn: cannot create %s (no /data volume mounted?): %v", d, err)
			break
		}
	}

	st, err := store.Load("/data/db/state.json")
	if err != nil {
		log.Fatalf("load state: %v", err)
	}
	api.EnsureAdmin(st)

	sup := supervisor.New(confPath())

	// render state -> config and test before nginx ever starts; a state that
	// renders invalid config is a bug and should fail the boot loudly
	if err := engine.Apply(&st.S, sup, false); err != nil {
		log.Fatalf("initial config render failed: %v", err)
	}
	if err := sup.Start(); err != nil {
		log.Fatalf("start nginx: %v", err)
	}
	log.Printf("super-nginx: nginx started (pid %d, conf %s)", sup.Pid(), sup.Conf)

	go certs.RenewLoop(st, func() error { return engine.Apply(&st.S, sup, true) })
	go serveUI(st, sup)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	select {
	case err := <-sup.Done():
		// ponytail: no in-process restart; exit and let the orchestrator restart us
		log.Fatalf("nginx exited: %v", err)
	case s := <-sigs:
		log.Printf("super-nginx: got %v, stopping nginx gracefully", s)
		sup.Stop()
	}
}

func serveUI(st *store.Store, sup *supervisor.Supervisor) {
	dist, err := fs.Sub(web.Dist, "dist")
	if err != nil {
		log.Fatalf("embedded UI: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServerFS(dist))
	api.New(st, sup).Register(mux)

	addr := ":8181"
	if p := os.Getenv("UI_PORT"); p != "" {
		addr = ":" + p
	}
	log.Printf("super-nginx: UI listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
