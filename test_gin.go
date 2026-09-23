package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/gin-gonic/gin"
)

func main() {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.GET("/stream", func(c *gin.Context) {
		start := time.Now()
		c.Stream(func(w io.Writer) bool {
			c.SSEvent("message", "hello")
			fmt.Printf("Wrote event at %v\n", time.Since(start))
			time.Sleep(2 * time.Second)
			return false
		})
	})
	
	req := httptest.NewRequest("GET", "/stream", nil)
	w := httptest.NewRecorder()
	
	go func() {
		r.ServeHTTP(w, req)
	}()
	
	time.Sleep(500 * time.Millisecond)
	fmt.Printf("Recorder body at 500ms: %q\n", w.Body.String())
}
