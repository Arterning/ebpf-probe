package probe

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"strings"
)

// nullTermStr converts a null-terminated byte slice to a Go string.
func nullTermStr(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n < 0 {
		return string(b)
	}
	return string(b[:n])
}

// uint32ToIPStr converts a big-endian uint32 to dotted-decimal notation.
func uint32ToIPStr(n uint32) string {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	return net.IP(b).String()
}

// isPrivateIP returns true if the IP is RFC 1918 / RFC 6598 / loopback.
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, cidr := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10",
		"127.0.0.0/8",
		"169.254.0.0/16",
	} {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// suspiciousDstPorts maps well-known attacker / reverse-shell ports to a description.
var suspiciousDstPorts = map[uint16]string{
	4444:  "common reverse shell",
	4445:  "common reverse shell alt",
	6666:  "common reverse shell",
	1234:  "common test/malware port",
	31337: "elite hacker port",
	9001:  "Tor / C2",
	9002:  "C2 common",
	8888:  "C2 common alt",
	2222:  "non-standard SSH",
}

// serverProcs is the set of process names that should not initiate outbound connections.
var serverProcs = map[string]bool{
	"nginx": true, "apache2": true, "httpd": true,
	"php-fpm": true, "php": true,
	"python3": true, "python": true,
	"node": true, "nodejs": true,
	"java": true, "ruby": true, "gunicorn": true,
}

// shellExecs is the set of executables considered interactive shells.
var shellExecs = map[string]bool{
	"/bin/bash": true, "/bin/sh": true, "/bin/zsh": true, "/bin/dash": true,
	"/usr/bin/bash": true, "/usr/bin/sh": true, "/usr/bin/zsh": true,
}

// readCmdline reads /proc/<pid>/cmdline and returns it as a space-joined string.
// Returns empty string if the process has already exited.
func readCmdline(pid uint32) string {
	data, err := os.ReadFile("/proc/" + itoa(pid) + "/cmdline")
	if err != nil {
		return ""
	}
	// cmdline args are NUL-separated
	parts := bytes.Split(data, []byte{0})
	strs := make([]string, 0, len(parts))
	for _, p := range parts {
		if len(p) > 0 {
			strs = append(strs, string(p))
		}
	}
	return strings.Join(strs, " ")
}

func itoa(n uint32) string {
	return strings.TrimSpace(string(append([]byte{}, encodeUint32(n)...)))
}

func encodeUint32(n uint32) []byte {
	if n == 0 {
		return []byte("0")
	}
	var buf [10]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return buf[pos:]
}
