// Command super-nginx supervises the bundled nginx and serves the management
// UI/API. Phase 0: supervisor + embedded UI + health endpoint only.
package main

import (
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"sync/atomic"
	"syscall"

	"github.com/morningstar-sudo/super-nginx/web"
)

const nginxBin = "/usr/sbin/nginx"

// Rendered configs and state live under /data (the single volume). The bridge
// files baked into the image include /data/nginx/*.d/*.conf.
var dataDirs = []string{
	"/data/nginx/conf.d",
	"/data/nginx/mail.d",
	"/data/nginx/stream.d",
	"/data/certs",
	"/data/db",
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

	conf := confPath()
	if out, err := exec.Command(nginxBin, "-t", "-c", conf).CombinedOutput(); err != nil {
		log.Printf("nginx config test failed (%s):\n%s", conf, out)
		os.Exit(1)
	}

	nginx := exec.Command(nginxBin, "-c", conf, "-g", "daemon off;")
	nginx.Stdout, nginx.Stderr = os.Stdout, os.Stderr
	if err := nginx.Start(); err != nil {
		log.Fatalf("start nginx: %v", err)
	}
	log.Printf("super-nginx: nginx started (pid %d, conf %s)", nginx.Process.Pid, conf)

	var running atomic.Bool
	running.Store(true)
	nginxDone := make(chan error, 1)
	go func() {
		err := nginx.Wait()
		running.Store(false)
		nginxDone <- err
	}()

	go serveUI(&running)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	select {
	case err := <-nginxDone:
		// ponytail: no in-process restart; exit and let the orchestrator restart us
		log.Fatalf("nginx exited: %v", err)
	case s := <-sigs:
		log.Printf("super-nginx: got %v, stopping nginx gracefully", s)
		_ = nginx.Process.Signal(syscall.SIGQUIT)
		<-nginxDone
	}
}

func serveUI(running *atomic.Bool) {
	dist, err := fs.Sub(web.Dist, "dist")
	if err != nil {
		log.Fatalf("embedded UI: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServerFS(dist))
	mux.HandleFunc("GET /api/v1/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status": "ok",
			"nginx":  map[string]bool{"running": running.Load()},
		})
	})

	addr := ":8181"
	if p := os.Getenv("UI_PORT"); p != "" {
		addr = ":" + p
	}
	log.Printf("super-nginx: UI listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
