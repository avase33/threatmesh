package hub

import (
	"strings"
	"testing"
)

func TestHubBroadcastAndRemove(t *testing.T) {
	h := New()
	c := h.Add()
	if h.Count() != 1 {
		t.Fatalf("want 1 client, got %d", h.Count())
	}
	h.Broadcast(map[string]string{"kind": "sqli"})
	msg := <-c.Send
	if !strings.Contains(string(msg), `"kind":"sqli"`) {
		t.Fatalf("unexpected broadcast: %s", msg)
	}
	h.Remove(c)
	if h.Count() != 0 {
		t.Fatalf("want 0 clients after remove, got %d", h.Count())
	}
}
