package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"asec-agent/config"
	"asec-agent/probe"
	"asec-agent/reporter"
)

const version = "1.0.0"

func main() {
	cfgPath := "agent.yaml"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	if cfg.Agent.HostIP == "" {
		cfg.Agent.HostIP = autoDetectIP()
	}
	if cfg.Agent.Hostname == "" {
		cfg.Agent.Hostname, _ = os.Hostname()
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	rep := reporter.New(reporter.Config{
		BackendURL: cfg.Backend.URL,
		APIKey:     cfg.Backend.APIKey,
		HostIP:     cfg.Agent.HostIP,
		Hostname:   cfg.Agent.Hostname,
		Interval:   cfg.Agent.FlushInterval,
		Version:    version,
	})

	flowProbe, err := probe.NewFlowProbe(rep)
	if err != nil {
		log.Fatalf("flow probe: %v", err)
	}
	defer flowProbe.Close()

	execProbe, err := probe.NewExecProbe(rep)
	if err != nil {
		log.Fatalf("exec probe: %v", err)
	}
	defer execProbe.Close()

	go flowProbe.Run(ctx)
	go execProbe.Run(ctx)
	go rep.Run(ctx)

	log.Printf("asec-agent %s started (ip=%s hostname=%s) → %s",
		version, cfg.Agent.HostIP, cfg.Agent.Hostname, cfg.Backend.URL)
	<-ctx.Done()
	log.Println("shutting down")
}

// autoDetectIP returns the preferred outbound IP of this machine.
func autoDetectIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}
