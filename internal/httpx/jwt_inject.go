package httpx

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// CloneRaw makes a shallow clone of RawRequest with a deep-copied Headers map + Body slice.
func CloneRaw(r *RawRequest) *RawRequest {
	h := make(map[string]string, len(r.Headers))
	for k, v := range r.Headers {
		h[k] = v
	}
	b := make([]byte, len(r.Body))
	copy(b, r.Body)
	return &RawRequest{
		Method:  r.Method,
		URL:     r.URL,
		Headers: h,
		Body:    b,
	}
}

// InjectByPlacement replaces the JWT according to the chosen placement kind (Authorization/Cookie/Header).
func InjectByPlacement(r *RawRequest, placement JWTPlacement, jwt string) (*RawRequest, string, error) {
	out := CloneRaw(r)

	switch placement.Kind {
	case PlaceCookie:
		if placement.Name == "" {
			return nil, "", fmt.Errorf("cookie placement missing Name")
		}
		setCookieHeader(out.Headers, placement.Name, jwt)
		return out, "cookie:" + placement.Name, nil

	case PlaceHeader:
		if placement.Name == "" {
			return nil, "", fmt.Errorf("header placement missing Name")
		}
		out.Headers[placement.Name] = jwt
		return out, "header:" + placement.Name, nil

	default: // Authorization Bearer
		out.Headers["Authorization"] = "Bearer " + jwt
		return out, "authorization:bearer", nil
	}
}

func InjectQueryParam(r *RawRequest, paramName, jwt string) (*RawRequest, string, error) {
	if strings.TrimSpace(paramName) == "" {
		return nil, "", fmt.Errorf("paramName is empty")
	}
	out := CloneRaw(r)

	u, err := url.Parse(out.URL)
	if err != nil {
		return nil, "", err
	}
	q := u.Query()
	q.Set(paramName, jwt)
	u.RawQuery = q.Encode()
	out.URL = u.String()
	return out, "query:" + paramName, nil
}

// InjectFormParam replaces/sets a form field in application/x-www-form-urlencoded bodies.
// If Content-Type is missing, we still try (common in raw requests).
func InjectFormParam(r *RawRequest, fieldName, jwt string) (*RawRequest, string, error) {
	if strings.TrimSpace(fieldName) == "" {
		return nil, "", fmt.Errorf("fieldName is empty")
	}
	out := CloneRaw(r)

	ct := strings.ToLower(strings.TrimSpace(out.Headers["Content-Type"]))
	if ct != "" && !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		return nil, "", fmt.Errorf("Content-Type not form-urlencoded (%s)", ct)
	}

	v, err := url.ParseQuery(string(out.Body))
	if err != nil {
		// If body isn't parseable as form, fail cleanly (we're explicitly not doing JSON/XML here).
		return nil, "", fmt.Errorf("body is not x-www-form-urlencoded")
	}

	v.Set(fieldName, jwt)
	// Stable-ish output for readability
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		for _, vv := range v[k] {
			parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(vv))
		}
	}
	out.Body = []byte(strings.Join(parts, "&"))
	if out.Headers["Content-Type"] == "" {
		out.Headers["Content-Type"] = "application/x-www-form-urlencoded"
	}
	return out, "form:" + fieldName, nil
}

func setCookieHeader(headers map[string]string, cookieName, cookieValue string) {
	// Find existing Cookie header (case-insensitive)
	var key string
	for k := range headers {
		if strings.EqualFold(k, "Cookie") {
			key = k
			break
		}
	}
	if key == "" {
		headers["Cookie"] = cookieName + "=" + cookieValue
		return
	}

	raw := headers[key]
	pairs := splitCookiePairs(raw)

	found := false
	for i := range pairs {
		n, _ := splitCookieNV(pairs[i])
		if n == cookieName {
			pairs[i] = cookieName + "=" + cookieValue
			found = true
		}
	}
	if !found {
		pairs = append(pairs, cookieName+"="+cookieValue)
	}
	headers[key] = strings.Join(pairs, "; ")
}

func splitCookiePairs(s string) []string {
	chunks := strings.Split(s, ";")
	out := make([]string, 0, len(chunks))
	for _, c := range chunks {
		c = strings.TrimSpace(c)
		if c != "" {
			out = append(out, c)
		}
	}
	return out
}

func splitCookieNV(pair string) (name, val string) {
	kv := strings.SplitN(pair, "=", 2)
	name = strings.TrimSpace(kv[0])
	if len(kv) == 2 {
		val = strings.TrimSpace(kv[1])
	}
	return name, val
}
