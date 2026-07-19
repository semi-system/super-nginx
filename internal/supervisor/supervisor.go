// Package supervisor runs nginx as a child process so config test, reload
// (SIGHUP) and graceful stop (SIGQUIT) work without a shell or docker.sock.
package supervisor

import (
	"fmt"
	"os"
	"os/exec"
	"sync/atomic"
	"syscall"
)

const nginxBin = "/usr/sbin/nginx"

type Supervisor struct {
	Conf    string
	Running atomic.Bool
	cmd     *exec.Cmd
	done    chan error
}

func New(conf string) *Supervisor {
	return &Supervisor{Conf: conf, done: make(chan error, 1)}
}

// Test runs nginx -t; on failure the combined output is returned as the error.
func (s *Supervisor) Test() error {
	out, err := exec.Command(nginxBin, "-t", "-c", s.Conf).CombinedOutput()
	if err != nil {
		return fmt.Errorf("nginx -t failed:\n%s", out)
	}
	return nil
}

func (s *Supervisor) Start() error {
	cmd := exec.Command(nginxBin, "-c", s.Conf, "-g", "daemon off;")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	s.cmd = cmd
	s.Running.Store(true)
	go func() {
		err := cmd.Wait()
		s.Running.Store(false)
		s.done <- err
	}()
	return nil
}

// Done fires once when nginx exits.
func (s *Supervisor) Done() <-chan error { return s.done }

func (s *Supervisor) Reload() error {
	if s.cmd == nil || !s.Running.Load() {
		return fmt.Errorf("nginx is not running")
	}
	return s.cmd.Process.Signal(syscall.SIGHUP)
}

// Stop signals graceful shutdown and waits for exit.
func (s *Supervisor) Stop() {
	if s.cmd == nil || !s.Running.Load() {
		return
	}
	_ = s.cmd.Process.Signal(syscall.SIGQUIT)
	<-s.done
}

func (s *Supervisor) Pid() int {
	if s.cmd == nil {
		return 0
	}
	return s.cmd.Process.Pid
}
