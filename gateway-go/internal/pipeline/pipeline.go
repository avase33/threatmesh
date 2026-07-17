// Package pipeline moves batches of raw log lines through the Rust normalizer and
// the Python detector, and broadcasts any resulting threat alerts to the SIEM.
package pipeline

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"

	"github.com/avase33/threatmesh/gateway/internal/config"
	"github.com/avase33/threatmesh/gateway/internal/hub"
)

type Queue struct {
	ch chan []string
}

func NewQueue(buffer int) *Queue { return &Queue{ch: make(chan []string, buffer)} }

func (q *Queue) Push(lines []string) bool {
	if len(lines) == 0 {
		return true
	}
	select {
	case q.ch <- lines:
		return true
	default:
		return false
	}
}

func (q *Queue) Chan() <-chan []string { return q.ch }

type Alert struct {
	Ts           float64 `json:"ts"`
	IP           string  `json:"ip"`
	Score        float64 `json:"score"`
	Kind         string  `json:"kind"`
	Severity     string  `json:"severity"`
	Summary      string  `json:"summary"`
	FirewallRule string  `json:"firewall_rule"`
	Path         string  `json:"path"`
	Status       int     `json:"status"`
}

type incident struct {
	Severity     string `json:"severity"`
	Kind         string `json:"kind"`
	Summary      string `json:"summary"`
	FirewallRule string `json:"firewall_rule"`
}

type scoreResult struct {
	Index    int       `json:"index"`
	Anomaly  bool      `json:"anomaly"`
	Score    float64   `json:"score"`
	Incident *incident `json:"incident"`
}

type Pool struct {
	cfg   config.Config
	queue *Queue
	hub   *hub.Hub
	http  *http.Client
}

func NewPool(cfg config.Config, q *Queue, h *hub.Hub) *Pool {
	return &Pool{cfg: cfg, queue: q, hub: h, http: &http.Client{Timeout: 5 * time.Second}}
}

func (p *Pool) Run() {
	for i := 0; i < max(1, p.cfg.Workers); i++ {
		go p.loop()
	}
}

func (p *Pool) loop() {
	for batch := range p.queue.Chan() {
		p.process(batch)
	}
}

// BuildAlert is exported for testing the record→alert mapping.
func BuildAlert(rec map[string]any, res scoreResult) Alert {
	a := Alert{Ts: float64(time.Now().Unix()), Score: res.Score}
	if v, ok := rec["ip"].(string); ok {
		a.IP = v
	}
	if v, ok := rec["path"].(string); ok {
		a.Path = v
	}
	if v, ok := rec["status"].(float64); ok {
		a.Status = int(v)
	}
	if res.Incident != nil {
		a.Kind = res.Incident.Kind
		a.Severity = res.Incident.Severity
		a.Summary = res.Incident.Summary
		a.FirewallRule = res.Incident.FirewallRule
	}
	return a
}

func (p *Pool) process(batch []string) {
	records := p.normalize(batch)
	if len(records) == 0 {
		return
	}
	for _, res := range p.score(records) {
		if res.Anomaly && res.Index >= 0 && res.Index < len(records) {
			p.hub.Broadcast(BuildAlert(records[res.Index], res))
		}
	}
}

func (p *Pool) normalize(lines []string) []map[string]any {
	var out struct {
		Records []map[string]any `json:"records"`
	}
	if err := p.postJSON(p.cfg.NormalizerURL+"/normalize", map[string]any{"lines": lines}, &out); err != nil {
		return nil
	}
	return out.Records
}

func (p *Pool) score(records []map[string]any) []scoreResult {
	var out struct {
		Results []scoreResult `json:"results"`
	}
	if err := p.postJSON(p.cfg.DetectorURL+"/score", map[string]any{"records": records}, &out); err != nil {
		return nil
	}
	return out.Results
}

func (p *Pool) postJSON(url string, payload any, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	resp, err := p.http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(out)
}
