package report

import (
	"encoding/json"
	"io"
)

func PrintJSON(w io.Writer, r *Run) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
