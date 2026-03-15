package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

// ---- report payload types ----

type FlowReport struct {
	Pid       uint32 `json:"pid"`
	Uid       uint32 `json:"uid"`
	Comm      string `json:"comm"`
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	SrcPort   uint16 `json:"src_port"`
	DstPort   uint16 `json:"dst_port"`
	Direction uint8  `json:"direction"` // 0=outbound 1=inbound
}

type ExecReport struct {
	Pid      uint32 `json:"pid"`
	Uid      uint32 `json:"uid"`
	Comm     string `json:"comm"`
	Filename string `json:"filename"`
	Args     string `json:"args"`
}

type ProcessAlert struct {
	AlertType string `json:"alert_type"`
	Severity  string `json:"severity"` // low/medium/high/critical
	Pid       uint32 `json:"pid"`
	Comm      string `json:"comm"`
	DstIP     string `json:"dst_ip,omitempty"`
	DstPort   uint16 `json:"dst_port,omitempty"`
	Detail    string `json:"detail"` // JSON string
}

// ---- request envelopes sent to backend ----

type heartbeatReq struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	Version  string `json:"version"`
}

type flowsReq struct {
	IP       string       `json:"ip"`
	Hostname string       `json:"hostname"`
	Flows    []FlowReport `json:"flows"`
}

type execsReq struct {
	IP       string       `json:"ip"`
	Hostname string       `json:"hostname"`
	Events   []ExecReport `json:"events"`
}

type alertsReq struct {
	IP       string         `json:"ip"`
	Hostname string         `json:"hostname"`
	Alerts   []ProcessAlert `json:"alerts"`
}

// ---- Config & Reporter ----

type Config struct {
	BackendURL string
	APIKey     string
	HostIP     string
	Hostname   string
	Interval   int // seconds between flushes
	Version    string
}

type Reporter struct {
	cfg      Config
	client   *http.Client
	mu       sync.Mutex
	flows    []FlowReport
	execs    []ExecReport
	alerts   []ProcessAlert
}

func New(cfg Config) *Reporter {
	return &Reporter{
		cfg:    cfg,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (r *Reporter) QueueFlow(f FlowReport)   { r.mu.Lock(); r.flows = append(r.flows, f); r.mu.Unlock() }
func (r *Reporter) QueueExec(e ExecReport)   { r.mu.Lock(); r.execs = append(r.execs, e); r.mu.Unlock() }
func (r *Reporter) QueueAlert(a ProcessAlert) { r.mu.Lock(); r.alerts = append(r.alerts, a); r.mu.Unlock() }

func (r *Reporter) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(r.cfg.Interval) * time.Second)
	defer ticker.Stop()

	// Heartbeat immediately on start
	r.sendHeartbeat()

	heartbeatTicker := time.NewTicker(30 * time.Second)
	defer heartbeatTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			r.flush()
			return
		case <-ticker.C:
			r.flush()
		case <-heartbeatTicker.C:
			r.sendHeartbeat()
		}
	}
}

func (r *Reporter) flush() {
	r.mu.Lock()
	flows := r.flows
	execs := r.execs
	alerts := r.alerts
	r.flows = nil
	r.execs = nil
	r.alerts = nil
	r.mu.Unlock()

	if len(flows) > 0 {
		r.post("/v1/agent/flows", flowsReq{IP: r.cfg.HostIP, Hostname: r.cfg.Hostname, Flows: flows})
	}
	if len(execs) > 0 {
		r.post("/v1/agent/execs", execsReq{IP: r.cfg.HostIP, Hostname: r.cfg.Hostname, Events: execs})
	}
	if len(alerts) > 0 {
		r.post("/v1/agent/alerts", alertsReq{IP: r.cfg.HostIP, Hostname: r.cfg.Hostname, Alerts: alerts})
	}
}

func (r *Reporter) sendHeartbeat() {
	r.post("/v1/agent/heartbeat", heartbeatReq{
		IP:       r.cfg.HostIP,
		Hostname: r.cfg.Hostname,
		Version:  r.cfg.Version,
	})
}

func (r *Reporter) post(path string, body any) {
	data, err := json.Marshal(body)
	if err != nil {
		log.Printf("reporter: marshal error: %v", err)
		return
	}

	url := r.cfg.BackendURL + path
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		log.Printf("reporter: build request error: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", r.cfg.APIKey)

	resp, err := r.client.Do(req)
	if err != nil {
		log.Printf("reporter: POST %s error: %v", path, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		log.Printf("reporter: POST %s returned %d", path, resp.StatusCode)
	}
}

func (r *Reporter) String() string {
	return fmt.Sprintf("Reporter{url=%s host=%s}", r.cfg.BackendURL, r.cfg.HostIP)
}
