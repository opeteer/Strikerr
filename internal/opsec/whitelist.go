package opsec

import (
	"archive/zip"
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"golang.org/x/net/publicsuffix"

	"github.com/bits-and-blooms/bloom/v3"
)

var (
	whitelistFilter *bloom.BloomFilter
	whitelistMutex  sync.RWMutex
	downloadURL     = "https://tranco-list.eu/top-1m.csv.zip"
)

// InitWhitelist starts the asynchronous loading of the whitelist.
func InitWhitelist() {
	go func() {
		err := loadOrDownloadWhitelist()
		if err != nil {
			log.Printf("[OPSEC] Failed to load whitelist: %v", err)
		}
	}()
}

func loadOrDownloadWhitelist() error {
	dataDir := "./data"
	os.MkdirAll(dataDir, 0755)
	zipPath := filepath.Join(dataDir, "top-1m.csv.zip")

	info, err := os.Stat(zipPath)
	if err == nil && time.Since(info.ModTime()) < 24*time.Hour {
		log.Printf("[OPSEC] Using existing Tranco whitelist: %s", zipPath)
		if err := extractAndLoadBloomFilter(zipPath); err == nil {
			return nil
		} else {
			log.Printf("[OPSEC] Failed to load cached whitelist (%v), redownloading...", err)
		}
	}

	log.Printf("[OPSEC] Downloading Tranco whitelist...")
	err = downloadFile(zipPath, downloadURL)
	if err != nil {
		return err
	}

	return extractAndLoadBloomFilter(zipPath)
}

func downloadFile(filepath string, targetURL string) error {
	resp, err := http.Get(targetURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	tmpPath := filepath + ".tmp"
	out, err := os.Create(tmpPath)
	if err != nil {
		return err
	}

	_, err = io.Copy(out, resp.Body)
	out.Close() // Close before rename
	
	if err != nil {
		os.Remove(tmpPath)
		return err
	}

	return os.Rename(tmpPath, filepath)
}

func extractAndLoadBloomFilter(zipPath string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		if strings.HasSuffix(f.Name, ".csv") {
			rc, err := f.Open()
			if err != nil {
				return err
			}
			defer rc.Close()

			return loadCSVToBloom(rc)
		}
	}
	return nil
}

func loadCSVToBloom(r io.Reader) error {
	filter := bloom.NewWithEstimates(1000000, 0.01)

	scanner := bufio.NewScanner(r)
	count := 0
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ",", 2)
		if len(parts) == 2 {
			domain := strings.TrimSpace(parts[1])
			filter.AddString(domain)
			count++
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	whitelistMutex.Lock()
	whitelistFilter = filter
	whitelistMutex.Unlock()

	log.Printf("[OPSEC] Successfully loaded %d domains into Whitelist Bloom Filter", count)
	return nil
}

// extractDomain cleanly gets the hostname from a URL or domain string.
func extractDomain(u string) string {
	u = strings.ToLower(strings.TrimSpace(u))
	if !strings.Contains(u, "://") && !strings.HasPrefix(u, "//") {
		u = "http://" + u
	}
	parsed, err := url.Parse(u)
	var host string
	if err != nil {
		host = u
	} else {
		host = parsed.Hostname()
	}
	
	host = strings.TrimSuffix(host, ".")
	
	baseDomain, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err == nil {
		return baseDomain
	}
	return host
}

// IsWhitelisted checks if the domain is in the top 1M whitelist.
func IsWhitelisted(rawURL string) bool {
	whitelistMutex.RLock()
	defer whitelistMutex.RUnlock()

	if whitelistFilter == nil {
		return false
	}

	domain := extractDomain(rawURL)
	return whitelistFilter.TestString(domain)
}
