package main

import (
	"fmt"
	"net/http"
)

func main() {
	resp, err := http.Get("http://127.0.0.1:8051/api/v1/stats/stream")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	fmt.Println(resp.Status)
	buf := make([]byte, 200)
	n, _ := resp.Body.Read(buf)
	fmt.Println(string(buf[:n]))
}
