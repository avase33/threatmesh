// Package config loads gateway settings from the environment.
package config

import (
	"os"
	"strconv"
)

type Config struct {
	HTTPAddr      string // HTTP + WebSocket listen address
	UDPAddr       string // syslog/UDP listener ("" disables)
	TCPAddr       string // newline-stream TCP listener ("" disables)
	NormalizerURL string // Rust normalizer base URL
	DetectorURL   string // Python detector base URL
	Workers       int
}

func Load() Config {
	return Config{
		HTTPAddr:      env("THREATMESH_HTTP_ADDR", ":8080"),
		UDPAddr:       env("THREATMESH_UDP_ADDR", ":5514"),
		TCPAddr:       env("THREATMESH_TCP_ADDR", ":5515"),
		NormalizerURL: env("THREATMESH_NORMALIZER_URL", "http://localhost:8090"),
		DetectorURL:   env("THREATMESH_DETECTOR_URL", "http://localhost:8000"),
		Workers:       envInt("THREATMESH_WORKERS", 4),
	}
}

func env(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v, ok := os.LookupEnv(k); ok {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
