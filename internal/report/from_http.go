package report

import "jwtknife/internal/httpx"

func FromHTTPResult(r httpx.Result) *HTTPObs {
	return &HTTPObs{
		Status:   r.Status,
		BodyLen: r.BodyLen,
		Duration: r.Duration,
		Err:      r.Err,
	}
}
