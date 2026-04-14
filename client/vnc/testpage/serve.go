//go:build ignore

// Simple file server for the VNC test page.
// Usage: go run serve.go
// Then open: http://localhost:9090?host=100.0.23.250
package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
)

func main() {
	// Serve from the dashboard's public dir (has wasm, noVNC, etc.)
	dashboardPublic := os.Getenv("DASHBOARD_PUBLIC")
	if dashboardPublic == "" {
		home, _ := os.UserHomeDir()
		dashboardPublic = filepath.Join(home, "dev", "dashboard", "public")
	}

	// Serve test page index.html from this directory
	testDir, _ := os.Getwd()

	mux := http.NewServeMux()
	// Test page itself
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			http.ServeFile(w, r, filepath.Join(testDir, "index.html"))
			return
		}
		// Everything else from dashboard public (wasm, noVNC, etc.)
		http.FileServer(http.Dir(dashboardPublic)).ServeHTTP(w, r)
	})

	addr := ":9090"
	fmt.Printf("VNC test page: http://localhost%s?host=<peer_ip>\n", addr)
	fmt.Printf("Serving assets from: %s\n", dashboardPublic)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(1)
	}
}
