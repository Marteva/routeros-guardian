package routeros

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

func TestDropConnections(t *testing.T) {
	var mu sync.Mutex
	var deleted []string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/rest/ip/firewall/connection":
			w.Write([]byte(`[
				{".id":"*1","src-address":"192.168.88.10:5000","dst-address":"1.1.1.1:443"},
				{".id":"*2","src-address":"192.168.88.11:5000","dst-address":"1.1.1.1:443"},
				{".id":"*3","src-address":"8.8.8.8:53","dst-address":"192.168.88.10:4000"},
				{".id":"*4","src-address":"192.168.88.10","dst-address":"9.9.9.9"},
				{".id":"*5","src-address":"192.168.88.10:1","dst-address":"2.2.2.2:1"}
			]`))
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/rest/ip/firewall/connection/"):
			id := strings.TrimPrefix(r.URL.Path, "/rest/ip/firewall/connection/")
			if id == "*5" { // vanished concurrently
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"error":404,"message":"Not Found"}`))
				return
			}
			mu.Lock()
			deleted = append(deleted, id)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	})
	n, err := c.DropConnections(context.Background(), netip.MustParseAddr("192.168.88.10"))
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 || strings.Join(deleted, ",") != "*1,*3,*4" {
		t.Fatalf("n=%d deleted=%v", n, deleted)
	}
}
