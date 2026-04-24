package dockerutil

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type CleanupFunc func()

// EnsureAvailable makes sure the Docker daemon is reachable.
// On this VPS we rely on systemd, so if the daemon is not active we start it
// and return a cleanup function that stops it only when jwtknife started it.
func EnsureAvailable() (CleanupFunc, error) {
	if err := dockerInfo(); err == nil {
		return func() {}, nil
	}

	if _, err := exec.LookPath("systemctl"); err != nil {
		return nil, fmt.Errorf("docker is unavailable and systemctl was not found: %w", err)
	}

	start := exec.Command("systemctl", "start", "docker")
	if out, err := start.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("starting docker failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if err := dockerInfo(); err == nil {
			return func() {
				stop := exec.Command("systemctl", "stop", "docker")
				_, _ = stop.CombinedOutput()
			}, nil
		}
		time.Sleep(500 * time.Millisecond)
	}

	return nil, fmt.Errorf("docker did not become ready after service start")
}

func dockerInfo() error {
	cmd := exec.Command("docker", "info")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("docker info failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}
