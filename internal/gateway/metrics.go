package gateway

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/NikhilSetiya/stopbar/internal/model"
)

// metrics is a minimal Prometheus text-format exporter. Hand-rolled to keep
// the request path stdlib-only. Label values are bounded (fixed routes,
// typed codes, three outcomes), so cardinality cannot grow with input.
type metrics struct {
	mu         sync.Mutex
	requests   map[[2]string]uint64 // {route, status}
	rejections map[string]uint64    // code
	decisions  map[string]uint64    // outcome
}

func newMetrics() *metrics {
	return &metrics{requests: map[[2]string]uint64{}, rejections: map[string]uint64{}, decisions: map[string]uint64{}}
}

func (m *metrics) request(route string, status int) {
	m.mu.Lock()
	m.requests[[2]string{route, strconv.Itoa(status)}]++
	m.mu.Unlock()
}

func (m *metrics) rejection(c Code) {
	m.mu.Lock()
	m.rejections[string(c)]++
	m.mu.Unlock()
}

func (m *metrics) decision(o model.Outcome) {
	m.mu.Lock()
	m.decisions[string(o)]++
	m.mu.Unlock()
}

// render returns the exposition text; built in memory so the response is a
// single write.
func (m *metrics) render() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var w strings.Builder
	w.WriteString("# HELP stopbar_http_requests_total HTTP responses by route and status.\n")
	w.WriteString("# TYPE stopbar_http_requests_total counter\n")
	keys := make([][2]string, 0, len(m.requests))
	for k := range m.requests {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i][0] != keys[j][0] {
			return keys[i][0] < keys[j][0]
		}
		return keys[i][1] < keys[j][1]
	})
	for _, k := range keys {
		fmt.Fprintf(&w, "stopbar_http_requests_total{route=%q,status=%q} %d\n", k[0], k[1], m.requests[k])
	}
	writeCounter(&w, "stopbar_gateway_rejections_total", "Requests rejected by the gateway, by error code.", "code", m.rejections)
	writeCounter(&w, "stopbar_decisions_total", "Decisions returned, by outcome.", "outcome", m.decisions)
	return w.String()
}

func writeCounter(w *strings.Builder, name, help, label string, vals map[string]uint64) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", name, help, name)
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(w, "%s{%s=%q} %d\n", name, label, k, vals[k])
	}
}

// renderCounters renders plain named counters, sorted by name.
func renderCounters(c map[string]uint64) string {
	names := make([]string, 0, len(c))
	for n := range c {
		names = append(names, n)
	}
	sort.Strings(names)
	var w strings.Builder
	for _, n := range names {
		fmt.Fprintf(&w, "# TYPE %s counter\n%s %d\n", n, n, c[n])
	}
	return w.String()
}
