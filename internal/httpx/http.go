package httpx

import (
	"io"
	"net/http"
	"time"
)

type PlacementKind int

const (
	PlaceAuthorizationBearer PlacementKind = iota
	PlaceCookie
	PlaceHeader
)

type JWTPlacement struct {
	Kind PlacementKind
	Name string
}

type Targets struct {
	PublicURL string
	AuthURL   string
	AdminURL  string
	Method    string
	Placement JWTPlacement
}

type RequestPlan struct {
	Label     string
	URL       string
	Method    string
	JWT       string
	Placement JWTPlacement
}

type ClientOpts struct {
	Timeout         time.Duration
	FollowRedirects bool
	MaxRequests     int
	DryRun          bool
	NoHTTP          bool
}

type Client struct {
	hc   *http.Client
	opts ClientOpts
}

func NewClient(o ClientOpts) *Client {
	h := &http.Client{Timeout: o.Timeout}
	if !o.FollowRedirects {
		h.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return &Client{hc: h, opts: o}
}

type Result struct {
	Label    string
	Status   int
	BodyLen  int
	Body     []byte
	Duration time.Duration
	Err      string
}

func (r Result) BodyText() string {
	return string(r.Body)
}

func (c *Client) Do(p RequestPlan) Result {
	if c.opts.NoHTTP || c.opts.DryRun {
		return Result{Label: p.Label}
	}

	req, err := http.NewRequest(p.Method, p.URL, nil)
	if err != nil {
		return Result{Label: p.Label, Err: err.Error()}
	}

	switch p.Placement.Kind {
	case PlaceCookie:
		req.AddCookie(&http.Cookie{Name: p.Placement.Name, Value: p.JWT})
	case PlaceHeader:
		req.Header.Set(p.Placement.Name, p.JWT)
	default:
		req.Header.Set("Authorization", "Bearer "+p.JWT)
	}

	start := time.Now()
	resp, err := c.hc.Do(req)
	if err != nil {
		return Result{Label: p.Label, Err: err.Error()}
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return Result{
		Label:    p.Label,
		Status:   resp.StatusCode,
		BodyLen:  len(b),
		Body:     b,
		Duration: time.Since(start),
	}
}
