# Rencana Implementasi Teknis: Sistem Deteksi Pintar Strikerr (Mengurangi False Positives)

Dokumen ini menjelaskan rancangan arsitektur dan implementasi teknis untuk tiga metode deteksi canggih pada proyek Strikerr menggunakan bahasa pemrograman Go. Tujuannya adalah untuk menurunkan tingkat *false positive* secara drastis dengan pendekatan analisis yang lebih realistis dan terstruktur.

## 1. Threat Intelligence, Whitelisting & Domain Reputation (Bloom Filters)

### Konsep
Saat ini, semua domain yang masuk berpotensi dipindai dengan bobot yang sama. Kita perlu menerapkan *whitelisting* skala besar (contoh: Tranco Top 1M atau daftar domain pemerintah yang valid) agar tidak membuang sumber daya dan meminimalisir *false positive* pada domain tepercaya.

### Implementasi Teknis (Golang)
Karena daftar *whitelist* bisa sangat besar (jutaan *record*), penggunaan *map* biasa akan memakan memori berlebih. Kita akan menggunakan **Bloom Filter**, struktur data probabilistik yang sangat hemat memori untuk mengecek apakah suatu elemen *pasti tidak ada* atau *mungkin ada* dalam *set*.

**Library yang disarankan:** `github.com/bits-and-blooms/bloom/v3`

**Contoh Struktur Kode (misal di `internal/opsec/whitelist.go`):**
```go
package opsec

import (
	"bufio"
	"os"
	"github.com/bits-and-blooms/bloom/v3"
)

type DomainReputation struct {
	whitelistFilter *bloom.BloomFilter
}

func NewDomainReputation(expectedElements uint, falsePositiveRate float64) *DomainReputation {
	return &DomainReputation{
		whitelistFilter: bloom.NewWithEstimates(expectedElements, falsePositiveRate),
	}
}

// LoadFromCSV memuat domain seperti Tranco ke dalam Bloom Filter
func (dr *DomainReputation) LoadFromCSV(filepath string) error {
	file, err := os.Open(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := scanner.Text()
		dr.whitelistFilter.AddString(domain)
	}
	return scanner.Err()
}

// IsWhitelisted memeriksa dengan cepat (O(k))
func (dr *DomainReputation) IsWhitelisted(domain string) bool {
	return dr.whitelistFilter.TestString(domain)
}
```
**Integrasi:** Panggil `IsWhitelisted` sebelum proses `ParseDOM` atau perayapan mendalam. Jika `true`, kurangi skor atau lewati deteksi ancaman kecuali ada indikasi kuat lainnya (*override* khusus).

---

## 2. DOM Structural & Form Heuristics (goquery)

### Konsep
Berdasarkan kode `internal/extractor/dom_parser.go` saat ini, sistem hanya menggunakan `strings.Contains` untuk mencocokkan *keyword*. Pendekatan ini rentan terhadap *false positive* (contoh: situs portal berita yang membahas penangkapan sindikat "judi online" akan langsung dianggap sebagai situs judol). Kita perlu menganalisis *struktur* DOM halaman.

### Implementasi Teknis (Golang)
Kita akan mem-parsing elemen HTML menggunakan **goquery**, sebuah *library* Golang populer dengan kapabilitas seperti *selector* jQuery untuk mengekstrak data dari DOM secara spesifik.

**Library yang disarankan:** `github.com/PuerkitoBio/goquery`

**Contoh Struktur Kode (misal memperbarui `internal/extractor/dom_parser.go`):**
```go
package extractor

import (
	"strings"
	"github.com/PuerkitoBio/goquery"
)

// Menambahkan field baru pada ExtractedInfo di dom_parser.go
// HasLoginForm bool
// HasHiddenIframe bool

func ParseDOMStructural(html string) (ExtractedInfo, error) {
	info := ExtractedInfo{}
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		return info, err
	}

	// Heuristik 1: Form Login mencurigakan
	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		action, exists := s.Attr("action")
		// Jika form memiliki input type="password"
		hasPassword := s.Find("input[type='password']").Length() > 0
		
		if hasPassword {
			info.HasLoginForm = true
			// Periksa apakah action mengarah ke URL mencurigakan
			if exists && (strings.HasPrefix(action, "http://") || strings.Contains(action, ".php")) {
				info.HasPhishing = true
			}
		}
	})

	// Heuristik 2: Iframe tersembunyi (sering dipakai injeksi judol/SEO cloaking)
	doc.Find("iframe").Each(func(i int, s *goquery.Selection) {
		style, exists := s.Attr("style")
		if exists && (strings.Contains(style, "display:none") || strings.Contains(style, "visibility:hidden")) {
			info.HasCloaking = true 
			info.HasHiddenIframe = true
		}
	})

	return info, nil
}
```
**Integrasi:** Ekstraksi terstruktur ini dijalankan untuk memverifikasi temuan teks biasa. Temuan `hasPhishing` dari teks hanya berbobot besar jika ada struktur `<form>` yang sesuai di dalam DOM.

---

## 3. Dynamic Scoring Matrix (Fuzzy Logic & Decision Trees)

### Konsep
Di dalam file `internal/scoring/matrix.go` saat ini, sistem menambahkan skor konstan secara kaku (`score += WeightJudolKeyword`). Pendekatan ini kurang kontekstual. Kita harus mengubahnya dengan model pohon keputusan (Decision Tree) atau logika fuzzy yang memperhitungkan korelasi beberapa elemen yang ada pada halaman sebelum menjatuhkan vonis skor ancaman.

### Implementasi Teknis (Golang)
Membangun matriks atau fungsi pembantu yang mengevaluasi relasi dari `ExtractedInfo` dan status `Whitelist`.

**Contoh Struktur Kode (refaktor `internal/scoring/matrix.go`):**
```go
package scoring

import "github.com/opeteer/strikerr/internal/extractor"

// Context adalah wrapper untuk berbagai sumber intelijen yang diekstrak
type Context struct {
	IsWhitelisted  bool
	HasLoginForm   bool
	HasHiddenIframe bool
	// Tambahan parameter untuk logika fuzzy
}

func CalculateDynamicScore(info extractor.ExtractedInfo, ctx Context) int {
	score := 0

	// Logika 1: Whitelisting (Domain Reputasi) akan menekan false positive
	if ctx.IsWhitelisted {
		// Jika domain aman dan tidak ada anomali injeksi iframe/cloaking
		if !ctx.HasHiddenIframe && !info.HasCloaking {
			return 0 // Anggap sebagai false positive (misal artikel berita kompas.com bahas judol)
		}
		// Namun jika terdeteksi iframe judi tersembunyi di web kompas, bisa jadi web tersebut terkena deface
		score += 30 
	}

	// Logika 2: Analisis Kontekstual Phishing
	if info.HasPhishing {
		if ctx.HasLoginForm {
			score += 65 // Kepastian tinggi karena ada form input
		} else {
			score += 10 // Kemungkinan hanya bahasan teks artikel tentang phishing
		}
	}

	// Logika 3: Analisis Injeksi Judi Online (Judol)
	if info.HasGambling {
		if ctx.HasHiddenIframe || info.HasCloaking {
			score += 75 // Indikasi kuat adanya script SEO spam / defacement judol
		} else {
			score += 15 // Berisiko rendah karena mungkin hanya string semata
		}
	}

	// Normalisasi batas atas (Capping)
	if score > 100 {
		score = 100
	}
	return score
}
```
**Integrasi:** Struktur decision-tree ini memungkinkan engineer untuk terus menambahkan aturan (nodes) saat ada teknik serangan baru tanpa membuat kalkulasi linier saat ini rusak (*broken*). Untuk aturan yang lebih rumit lagi di masa depan, proyek dapat menggunakan *Rule Engine* berbasis DSL (seperti `grule-rule-engine`).

---

## 4. Web Interface Optimization & Real-Time Telemetry (SSE + ECharts)

### Konsep
Antarmuka web saat ini menggunakan metode polling untuk mendapatkan data statistik terbaru, yang tidak efisien dan menyebabkan beban tinggi pada server, ditambah dengan potensi race condition (cache stampede). Selain itu, grafik menggunakan Chart.js yang bisa dioptimalkan menggunakan ECharts untuk performa rendering dan interaktivitas yang lebih baik pada data bervolume besar.

### Implementasi Teknis
1. **Backend (Golang):**
   - Refaktor `APIGetStats` dengan mengekstrak kueri database ke dalam satu fungsi `fetchStatsData()` yang membungkus seluruh blok dengan `statsCacheLock.Lock()` dan `defer statsCacheLock.Unlock()` untuk mencegah cache stampede sepenuhnya.
   - Tambahkan endpoint `/api/v1/stats/stream` (handler `APIGetStatsSSE`) yang memanfaatkan Server-Sent Events (SSE) dengan mem-push data setiap 2 detik.
2. **Frontend (HTML/JS + Alpine.js):**
   - Migrasi dari Chart.js ke Apache ECharts (`echarts.init()`).
   - Ubah elemen kontainer grafik dari `<canvas>` ke `<div>` dengan properti class `w-full h-full` dan ID yang sesuai.
   - Ganti implementasi `setInterval` (polling) menjadi langganan ke `EventSource` untuk pembaruan waktu nyata.
