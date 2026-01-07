package jwtknifejwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

type Parsed struct {
	Raw         string
	Header      map[string]any
	Payload     map[string]any
	HeaderJSON  string
	PayloadJSON string

	Alg    string
	HasKid bool
	Kid    string

	HasJKU bool
	JKU    string

	HasJWK bool
}

func Parse(raw string) (*Parsed, error) {
	parts := strings.Split(strings.TrimSpace(raw), ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("expected 3 JWT parts, got %d", len(parts))
	}

	hb, err := b64urlDecode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("header decode: %w", err)
	}
	pb, err := b64urlDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("payload decode: %w", err)
	}

	var h map[string]any
	var p map[string]any
	if err := json.Unmarshal(hb, &h); err != nil {
		return nil, fmt.Errorf("header json: %w", err)
	}
	if err := json.Unmarshal(pb, &p); err != nil {
		return nil, fmt.Errorf("payload json: %w", err)
	}

	hPretty, _ := json.MarshalIndent(h, "", "  ")
	pPretty, _ := json.MarshalIndent(p, "", "  ")

	out := &Parsed{
		Raw:         raw,
		Header:      h,
		Payload:     p,
		HeaderJSON:  string(hPretty),
		PayloadJSON: string(pPretty),
	}

	if alg, ok := h["alg"].(string); ok && alg != "" {
		out.Alg = alg
	} else {
		out.Alg = "unknown"
	}

	if kid, ok := h["kid"].(string); ok && kid != "" {
		out.HasKid = true
		out.Kid = kid
	}
	if jku, ok := h["jku"].(string); ok && jku != "" {
		out.HasJKU = true
		out.JKU = jku
	}
	if _, ok := h["jwk"]; ok {
		out.HasJWK = true
	}

	return out, nil
}

// Rebuild rebuilds a JWT from the parsed header + payload.
// Signature is intentionally omitted (trailing dot kept).
func Rebuild(p *Parsed) (string, error) {
	hb, err := json.Marshal(p.Header)
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(p.Payload)
	if err != nil {
		return "", err
	}

	return b64urlEncode(hb) + "." + b64urlEncode(pb) + ".", nil
}

func b64urlDecode(s string) ([]byte, error) {
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return base64.URLEncoding.DecodeString(s)
}

func b64urlEncode(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}
