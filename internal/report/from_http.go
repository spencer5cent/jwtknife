package report

import "github.com/spencer5cent/jwtknife/internal/httpx"

func FromHTTPResult(r httpx.Result) *HTTPObs {
	return &HTTPObs{
		Status:   r.Status,
		BodyLen:  r.BodyLen,
		Duration: r.Duration,
		Err:      r.Err,
	}
}
