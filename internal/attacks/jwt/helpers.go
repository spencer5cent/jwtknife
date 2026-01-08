package jwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

func injectJWTHeader(token string, hdr map[string]any) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return token
	}

	hb, _ := json.Marshal(hdr)
	hEnc := base64.RawURLEncoding.EncodeToString(hb)

	// keep original payload + signature
	return hEnc + "." + parts[1] + "." + parts[2]
}
