// Command threatmesh-gateway ingests logs (UDP syslog, TCP stream, or HTTP),
// queues them for normalization + scoring, and streams threat alerts to the SIEM
// dashboard over WebSocket.
package main

import (
	"bufio"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/gorilla/websocket"

	"github.com/avase33/threatmesh/gateway/internal/config"
	"github.com/avase33/threatmesh/gateway/internal/hub"
	"github.com/avase33/threatmesh/gateway/internal/pipeline"
)

type App struct {
	cfg   config.Config
	queue *pipeline.Queue
	hub   *hub.Hub
}

var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

func splitLines(s string) []string {
	out := make([]string, 0, 8)
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimRight(ln, "\r")
		if strings.TrimSpace(ln) != "" {
			out = append(out, ln)
		}
	}
	return out
}

func (a *App) handleIngest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Lines []string `json:"lines"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	a.queue.Push(body.Lines)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{"accepted": len(body.Lines)})
}

func (a *App) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "ok", "service": "gateway", "clients": a.hub.Count(),
		"normalizer": a.cfg.NormalizerURL, "detector": a.cfg.DetectorURL,
	})
}

func (a *App) handleWSAlerts(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	client := a.hub.Add()
	defer func() {
		a.hub.Remove(client)
		conn.Close()
	}()
	go func() {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				a.hub.Remove(client)
				return
			}
		}
	}()
	for msg := range client.Send {
		if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
			return
		}
	}
}

func (a *App) startUDP() {
	if a.cfg.UDPAddr == "" {
		return
	}
	pc, err := net.ListenPacket("udp", a.cfg.UDPAddr)
	if err != nil {
		log.Printf("udp listen %s: %v", a.cfg.UDPAddr, err)
		return
	}
	log.Printf("syslog/udp listening on %s", a.cfg.UDPAddr)
	buf := make([]byte, 65535)
	for {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		a.queue.Push(splitLines(string(buf[:n])))
	}
}

func (a *App) startTCP() {
	if a.cfg.TCPAddr == "" {
		return
	}
	ln, err := net.Listen("tcp", a.cfg.TCPAddr)
	if err != nil {
		log.Printf("tcp listen %s: %v", a.cfg.TCPAddr, err)
		return
	}
	log.Printf("log/tcp listening on %s", a.cfg.TCPAddr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go a.handleConn(conn)
	}
}

func (a *App) handleConn(conn net.Conn) {
	defer conn.Close()
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	batch := make([]string, 0, 64)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			batch = append(batch, line)
		}
		if len(batch) >= 50 {
			a.queue.Push(batch)
			batch = make([]string, 0, 64)
		}
	}
	if len(batch) > 0 {
		a.queue.Push(batch)
	}
}

func main() {
	cfg := config.Load()
	app := &App{cfg: cfg, queue: pipeline.NewQueue(4096), hub: hub.New()}
	pipeline.NewPool(cfg, app.queue, app.hub).Run()

	go app.startUDP()
	go app.startTCP()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /ingest", app.handleIngest)
	mux.HandleFunc("GET /health", app.handleHealth)
	mux.HandleFunc("GET /ws/alerts", app.handleWSAlerts)

	log.Printf("threatmesh gateway (http %s) → normalizer=%s detector=%s",
		cfg.HTTPAddr, cfg.NormalizerURL, cfg.DetectorURL)
	if err := http.ListenAndServe(cfg.HTTPAddr, mux); err != nil {
		log.Fatal(err)
	}
}
