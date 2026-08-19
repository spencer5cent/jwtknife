package httpx

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

var (
	dynamicUUID  = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	dynamicHex   = regexp.MustCompile(`(?i)\b[0-9a-f]{16,}\b`)
	dynamicToken = regexp.MustCompile(`[A-Za-z0-9]{8,}[-_+/][A-Za-z0-9_+/=-]{8,}`)
	dynamicTime  = regexp.MustCompile(`\b[0-9]{10,}\b`)
	dynamicSpace = regexp.MustCompile(`\s+`)
)

// normalizedBodySHA256 masks common request/session nonces while retaining
// semantic text, keys, booleans, and short values. This lets repeated public or
// authenticated pages compare reliably without treating a changing nonce as an
// authorization boundary.
func normalizedBodySHA256(body []byte) string {
	normalized := strings.ToLower(string(body))
	normalized = dynamicUUID.ReplaceAllString(normalized, "<uuid>")
	normalized = dynamicHex.ReplaceAllString(normalized, "<hex>")
	normalized = dynamicToken.ReplaceAllString(normalized, "<token>")
	normalized = dynamicTime.ReplaceAllString(normalized, "<number>")
	normalized = dynamicSpace.ReplaceAllString(normalized, " ")
	sum := sha256.Sum256([]byte(strings.TrimSpace(normalized)))
	return hex.EncodeToString(sum[:])
}
