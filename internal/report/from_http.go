package report

import "github.com/spencer5cent/jwtknife/internal/httpx"

func FromHTTPResult(r httpx.Result) *HTTPObs {
	return &HTTPObs{
		Status:               r.Status,
		BodyLen:              r.BodyLen,
		BodySHA256:           r.BodySHA256,
		BodyNormalizedSHA256: r.BodyNormalizedSHA256,
		Duration:             r.Duration,
		Err:                  r.Err,
	}
}
