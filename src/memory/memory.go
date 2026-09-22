package memory

import (
	"github.com/google/gopacket/layers"
	"github.com/mostlygeek/arp"
)

type Info struct {
	DistinctPorts  int
	SYNs           int
	ACKs           int
	SSHConnections int
	FINs           int
	NullPackets    int
	XMASPackets    int
	ICMPs          int
	UDPs           int
	DNSRequests    int
	DNSResponses   int
	ARPMAC         string
	Ports          []layers.TCPPort
}

type Memory struct {
	Current  map[string]*Info
	Previous map[string]*Info
}

func New() *Memory {
	result := &Memory{
		Current:  make(map[string]*Info),
		Previous: make(map[string]*Info),
	}
	EnsureIP(result, "ALL")
	return result
}

func EnsureIP(state *Memory, ip string) {
	if _, ok := state.Current[ip]; !ok {
		state.Current[ip] = &Info{Ports: make([]layers.TCPPort, 0)}
	}
	if _, ok := state.Previous[ip]; !ok {
		state.Previous[ip] = &Info{Ports: make([]layers.TCPPort, 0)}
	}
}

func SeedARPCache(state *Memory) {
	for ip := range arp.Table() {
		EnsureIP(state, ip)
		state.Current[ip].ARPMAC = arp.Search(ip)
	}
}
