package pipeline

import "testing"

func TestQueuePushPop(t *testing.T) {
	q := NewQueue(1)
	if !q.Push([]string{"a"}) {
		t.Fatal("push should succeed")
	}
	if q.Push([]string{"b"}) {
		t.Fatal("second push should fail on a full queue")
	}
	b := <-q.Chan()
	if len(b) != 1 || b[0] != "a" {
		t.Fatalf("got %v", b)
	}
}

func TestQueueEmptyIsNoop(t *testing.T) {
	q := NewQueue(1)
	if !q.Push(nil) {
		t.Fatal("empty push should be a no-op returning true")
	}
	select {
	case <-q.Chan():
		t.Fatal("empty push should not enqueue")
	default:
	}
}

func TestBuildAlertMapsRecordAndIncident(t *testing.T) {
	rec := map[string]any{"ip": "1.2.3.4", "path": "/login", "status": float64(401)}
	res := scoreResult{
		Index:   0,
		Anomaly: true,
		Score:   0.83,
		Incident: &incident{
			Severity:     "medium",
			Kind:         "brute_force",
			Summary:      "brute force from 1.2.3.4",
			FirewallRule: "iptables -A INPUT -s 1.2.3.4 -j DROP",
		},
	}
	a := BuildAlert(rec, res)
	if a.IP != "1.2.3.4" || a.Status != 401 || a.Kind != "brute_force" || a.Score != 0.83 {
		t.Fatalf("unexpected alert: %+v", a)
	}
}
