// Package web serves the embedded natlab dashboard and its JSON artifacts.
package web

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"path"
)

//go:embed static/index.html
var staticFS embed.FS

// Server hosts the dashboard UI and the data files produced by the CLI.
type Server struct {
	dataDir string
	mux     *http.ServeMux
}

// NewServer builds a server reading JSON artifacts from dataDir. When dataDir
// is empty it serves only the embedded page (the page can also fetch from a
// file:// location or a separately hosted data directory).
func NewServer(dataDir string) *Server {
	s := &Server{dataDir: dataDir, mux: http.NewServeMux()}
	sub, _ := fs.Sub(staticFS, "static")
	s.mux.Handle("/", http.FileServer(http.FS(sub)))
	s.mux.HandleFunc("/data/", s.serveData)
	return s
}

func (s *Server) serveData(w http.ResponseWriter, r *http.Request) {
	if s.dataDir == "" {
		http.Error(w, "no data directory configured", http.StatusNotFound)
		return
	}
	name := path.Base(r.URL.Path) // never escape the data directory
	w.Header().Set("Content-Type", "application/json")
	b, err := os.ReadFile(path.Join(s.dataDir, name))
	if err != nil {
		http.Error(w, "artifact not found: "+name, http.StatusNotFound)
		return
	}
	// echo pretty-printed JSON
	var v any
	if json.Unmarshal(b, &v) == nil {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(v)
		return
	}
	_, _ = w.Write(b)
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler { return s.mux }

// ListenAndServe starts the dashboard on addr.
func (s *Server) ListenAndServe(addr string) error {
	return http.ListenAndServe(addr, s.mux)
}
