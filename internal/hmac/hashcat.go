package hmac

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

func RecoverSecret(rawJWT, alg, wordlist string) (string, error) {
	if !strings.HasPrefix(alg, "HS") {
		return "", errors.New("not an HMAC-signed JWT")
	}

	mode := "16500" // JWT (JSON Web Token)

	/* ======================
	   Step 1: crack
	   ====================== */

	args := []string{
		"-a", "0",
		"-m", mode,
		rawJWT,
	}

	if wordlist != "" {
		args = append(args, wordlist)
	}

	crackCmd := exec.Command("hashcat", args...)
	_ = crackCmd.Run() // ignore exit code (hashcat returns non-zero on success)

	/* ======================
	   Step 2: show result
	   ====================== */

	showCmd := exec.Command(
		"hashcat",
		"--show",
		"-m", mode,
		rawJWT,
	)

	var out bytes.Buffer
	showCmd.Stdout = &out
	showCmd.Stderr = &out

	if err := showCmd.Run(); err != nil {
		return "", fmt.Errorf("hashcat --show failed: %v", err)
	}

	for _, line := range strings.Split(out.String(), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, rawJWT+":") {
			secret := strings.TrimPrefix(line, rawJWT+":")
			secret = strings.TrimSpace(secret)
			if secret != "" {
				return secret, nil
			}
		}
	}

	return "", errors.New("no HMAC secret found")
}
