package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Backend BackendConfig `yaml:"backend"`
	Agent   AgentConfig   `yaml:"agent"`
}

type BackendConfig struct {
	URL    string `yaml:"url"`
	APIKey string `yaml:"api_key"`
}

type AgentConfig struct {
	// FlushInterval is how often (seconds) to batch-send events to the backend.
	FlushInterval int `yaml:"flush_interval"`
	// HostIP overrides auto-detected outbound IP.
	HostIP string `yaml:"host_ip"`
	// Hostname label sent with every report (defaults to os.Hostname).
	Hostname string `yaml:"hostname"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.Agent.FlushInterval <= 0 {
		cfg.Agent.FlushInterval = 5
	}
	return &cfg, nil
}
