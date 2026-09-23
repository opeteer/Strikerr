package opsec

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestWhitelistDownloadErrorHandling(t *testing.T) {
	// Create a mock server that returns 404
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("404 page not found"))
	}))
	defer srv.Close()

	downloadURL = srv.URL + "/top-1m.csv.zip"
	
	// Create an empty dummy file to test if it fails on bad zip
	dataDir := "./data"
	os.MkdirAll(dataDir, 0755)
	zipPath := filepath.Join(dataDir, "top-1m.csv.zip")
	os.WriteFile(zipPath, []byte("not a zip"), 0644)
	
	err := extractAndLoadBloomFilter(zipPath)
	if err == nil {
		t.Errorf("Expected error on invalid zip, got nil")
	}
	
	// Clean up and test download
	os.RemoveAll(dataDir)
	err = loadOrDownloadWhitelist()
	if err == nil {
		t.Errorf("Expected error on 404, got nil")
	}

	// Wait, since downloadFile only renames on success, the 404 won't create a bad file.
	// Let's verify it doesn't create a file when cache doesn't exist and download fails.
	os.RemoveAll(dataDir)
	
	err = loadOrDownloadWhitelist()
	if err == nil {
		t.Errorf("Expected error on 404, got nil")
	}

	if _, err := os.Stat(filepath.Join(dataDir, "top-1m.csv.zip")); err == nil {
		t.Errorf("Expected no zip file to be created on 404, but it exists")
	}
}

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"http://www.google.com", "google.com"},
		{"https://sub.sub.google.com/path", "google.com"},
		{"google.com", "google.com"},
		{"example.co.uk", "example.co.uk"},
		{"http://www.example.co.uk", "example.co.uk"},
		{"sub.example.co.uk", "example.co.uk"},
		{"http://localhost", "localhost"},
		{"127.0.0.1", "127.0.0.1"},
		{"google.com.", "google.com"},
		{"//google.com", "google.com"},
		{"tcp://10.0.0.1:80", "10.0.0.1"},
	}

	for _, tc := range tests {
		actual := extractDomain(tc.input)
		if actual != tc.expected {
			t.Errorf("extractDomain(%q) = %q, expected %q", tc.input, actual, tc.expected)
		}
	}
}
