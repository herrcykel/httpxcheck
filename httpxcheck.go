package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"sync"
	"time"
)

type CheckResult int32

const (
	HTTPS   CheckResult = 0
	HTTP    CheckResult = 1
	UNKNOWN CheckResult = 2
)

// Client hello msg
// https://tls.ulfheim.net/
const TLS_CH string = "\x16\x03\x01\x00\x4d\x01\x00\x00\x49\x03\x03\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x00\x00\x20\xcc\xa8\xcc\xa9\xc0\x2f\xc0\x30\xc0\x2b\xc0\x2c\xc0\x13\xc0\x09\xc0\x14\xc0\x0a\x00\x9c\x00\x9d\x00\x2f\x00\x35\xc0\x12\x00\x0a\x01\x00\x00\x00"

func check(host string, port int64) CheckResult {
	// if port == 443 {
	// 	return HTTPS
	// } else if port == 80 {
	// 	return HTTP
	// }

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
	if err != nil {
		return UNKNOWN
	}
	defer conn.Close()

	data := make([]byte, 7)
	fmt.Fprintf(conn, TLS_CH)
	conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	conn.Read(data)
	if (data[0] == 0x16 && data[5] == 0x02) || (data[0] == 0x15 && bytes.Compare([]byte{0x02, 0x28}, data[5:7]) == 0) {
		return HTTPS
	}
	if string(data[:5]) == "HTTP/" {
		return HTTP
	}
	conn.Close()

	conn, err = net.DialTimeout("tcp", addr, 200*time.Millisecond)
	if err != nil {
		return UNKNOWN
	}
	defer conn.Close()

	fmt.Fprintf(conn, "GET / HTTP/1.0\r\n\r\n")
	conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	conn.Read(data)
	if string(data[:5]) == "HTTP/" {
		return HTTP
	}
	return UNKNOWN
}

func main() {
	fi, _ := os.Stdin.Stat()
	if (fi.Mode() & os.ModeCharDevice) != 0 {
		return
	}

	input := make(chan string)

	var wg sync.WaitGroup
	n := 2 * runtime.NumCPU()
	// n = 16
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			re := regexp.MustCompile("(\\d+)/tcp.+?(\\d\\S+)")
			for in := range input {
				m := re.FindStringSubmatch(in)
				if len(m) < 3 {
					continue
				}
				ip := m[2]
				port, _ := strconv.ParseInt(m[1], 10, 32)
				res := check(ip, port)
				if res == HTTP {
					fmt.Printf("http://%s:%d\n", ip, port)
				} else if res == HTTPS {
					fmt.Printf("https://%s:%d\n", ip, port)
				}
			}

			wg.Done()
		}()
	}

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		input <- line
	}

	close(input)
	wg.Wait()
}
