// Package hub fans out threat alerts to every connected SIEM dashboard over
// WebSocket. One goroutine-safe registry; slow clients are dropped rather than
// blocking the ingest path.
package hub

import (
	"encoding/json"
	"sync"
)

type Client struct {
	Send chan []byte
}

type Hub struct {
	mu      sync.RWMutex
	clients map[*Client]struct{}
}

func New() *Hub { return &Hub{clients: make(map[*Client]struct{})} }

func (h *Hub) Add() *Client {
	c := &Client{Send: make(chan []byte, 64)}
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()
	return c
}

func (h *Hub) Remove(c *Client) {
	h.mu.Lock()
	if _, ok := h.clients[c]; ok {
		delete(h.clients, c)
		close(c.Send)
	}
	h.mu.Unlock()
}

func (h *Hub) Count() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// Broadcast marshals v and pushes it to every client without blocking.
func (h *Hub) Broadcast(v any) {
	msg, err := json.Marshal(v)
	if err != nil {
		return
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for c := range h.clients {
		select {
		case c.Send <- msg:
		default:
		}
	}
}
