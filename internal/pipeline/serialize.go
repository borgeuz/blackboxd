package pipeline

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"

	"github.com/borgeuz/blackboxd/internal/parser"
)

// SerializeBatchJSONLGzip produces gzip(JSONL): one entry per line,
// the whole stream compressed. Format the cloud ingest expects.
func SerializeBatchJSONLGzip(batch []*parser.LogEntry) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	enc := json.NewEncoder(gz)
	enc.SetEscapeHTML(false)
	for _, e := range batch {
		if err := enc.Encode(e); err != nil {
			gz.Close()
			return nil, fmt.Errorf("pipeline serialize: %w", err)
		}
	}
	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("pipeline gzip close: %w", err)
	}
	return buf.Bytes(), nil
}

// DecodeBatchJSONLGzip is the inverse, used by tests.
func DecodeBatchJSONLGzip(payload []byte) ([]*parser.LogEntry, error) {
	gz, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("pipeline gunzip: %w", err)
	}
	defer gz.Close()
	body, err := io.ReadAll(gz)
	if err != nil {
		return nil, fmt.Errorf("pipeline read gunzipped: %w", err)
	}
	var out []*parser.LogEntry
	dec := json.NewDecoder(bytes.NewReader(body))
	for dec.More() {
		var e parser.LogEntry
		if err := dec.Decode(&e); err != nil {
			return nil, fmt.Errorf("pipeline decode: %w", err)
		}
		out = append(out, &e)
	}
	return out, nil
}
