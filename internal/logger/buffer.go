package logger

import (
	"bytes"
	"sync"
)

type MemoryWriter struct {
	mu    sync.Mutex
	lines []string
	max   int
}

func NewMemoryWriter(maxLines int) *MemoryWriter {
	return &MemoryWriter{
		lines: make([]string, 0, maxLines),
		max:   maxLines,
	}
}

func (mw *MemoryWriter) Write(p []byte) (n int, err error) {
	mw.mu.Lock()
	defer mw.mu.Unlock()

	line := string(bytes.TrimRight(p, "\n"))
	mw.lines = append(mw.lines, line)
	if len(mw.lines) > mw.max {
		mw.lines = mw.lines[1:]
	}
	return len(p), nil
}

func (mw *MemoryWriter) GetLogs() []string {
	mw.mu.Lock()
	defer mw.mu.Unlock()
	res := make([]string, len(mw.lines))
	copy(res, mw.lines)
	return res
}

func (mw *MemoryWriter) Reset() {
	mw.mu.Lock()
	defer mw.mu.Unlock()
	mw.lines = make([]string, 0, mw.max)
}

var GlobalBuffer *MemoryWriter

func InitLogger() *MemoryWriter {
	GlobalBuffer = NewMemoryWriter(200)
	return GlobalBuffer
}
