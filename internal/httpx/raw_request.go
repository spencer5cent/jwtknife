package httpx

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type RawRequest struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte
}

func ParseRawRequest(raw string) (*RawRequest, error) {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	lines := strings.Split(raw, "\n")

	if len(lines) < 2 {
		return nil, fmt.Errorf("invalid raw request")
	}

	// Request line
	parts := strings.Split(lines[0], " ")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid request line")
	}
	method := strings.TrimSpace(parts[0])
	path := strings.TrimSpace(parts[1])

	headers := make(map[string]string)
	i := 1
	for ; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			i++
			break
		}
		kv := strings.SplitN(line, ":", 2)
		if len(kv) != 2 {
			continue
		}
		headers[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
	}

	host, ok := headers["Host"]
	if !ok {
		return nil, fmt.Errorf("missing Host header")
	}

	fullURL := "https://" + host + path

	var body []byte
	if i < len(lines) {
		body = []byte(strings.Join(lines[i:], "\n"))
	}

	return &RawRequest{
		Method:  method,
		URL:     fullURL,
		Headers: headers,
		Body:    body,
	}, nil
}

func (c *Client) DoRaw(r *RawRequest) Result {
	if c.opts.NoHTTP || c.opts.DryRun {
		return Result{Label: "raw-request", Body: nil}
	}

	req, err := http.NewRequest(r.Method, r.URL, bytes.NewReader(r.Body))
	if err != nil {
		return Result{Label: "raw-request", Err: err.Error()}
	}

	for k, v := range r.Headers {
		if strings.EqualFold(k, "Host") {
			continue
		}
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := c.hc.Do(req)
	if err != nil {
		return Result{Label: "raw-request", Err: err.Error()}
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	return Result{
		Label:    "raw-request",
		Status:   resp.StatusCode,
		Body:     b,
		BodyLen:  len(b),
		Duration: time.Since(start),
	}
}
