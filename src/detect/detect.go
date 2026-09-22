package detect

import (
	"fmt"
	"ids/logger"
	"ids/memory"
)

const (
	MaxSYNMinusACK = 5000
	MaxFIN         = 500
	MaxNull        = 500
	MaxXMAS        = 500
	MaxSSH         = 20
	MaxPorts       = 30
	MaxICMP        = 6000
	MaxUDP         = 10000
	MaxDNS         = 4000
)

func TCP(ip string, state *memory.Memory, output *logger.Logger) {
	current, previous := state.Current[ip], state.Previous[ip]
	if current.SYNs+previous.SYNs-current.ACKs-previous.ACKs > MaxSYNMinusACK {
		output.Write(fmt.Sprintf("[CRITICAL] TCP SYN Flood détecté. (Seuil: %d)", MaxSYNMinusACK), ip)
		current.SYNs, previous.SYNs = 0, 0
	}
	if current.SSHConnections+previous.SSHConnections > MaxSSH {
		output.Write(fmt.Sprintf("[WARNING] Tentative de SSH Brute Force. (%d tentatives)", current.SSHConnections+previous.SSHConnections), ip)
		current.SSHConnections, previous.SSHConnections = 0, 0
	}
	if current.DistinctPorts+previous.DistinctPorts > MaxPorts {
		output.Write(fmt.Sprintf("[WARNING] Scan de ports détecté. (%d ports touchés)", current.DistinctPorts+previous.DistinctPorts), ip)
		current.DistinctPorts, previous.DistinctPorts = 0, 0
	}
	if current.FINs+previous.FINs > MaxFIN {
		output.Write("[WARNING] TCP FIN Scan/Flood détecté.", ip)
		current.FINs, previous.FINs = 0, 0
	}
	if current.NullPackets+previous.NullPackets > MaxNull {
		output.Write("[WARNING] TCP Null Scan détecté.", ip)
		current.NullPackets, previous.NullPackets = 0, 0
	}
	if current.XMASPackets+previous.XMASPackets > MaxXMAS {
		output.Write("[WARNING] TCP XMAS Scan détecté.", ip)
		current.XMASPackets, previous.XMASPackets = 0, 0
	}
}

func ICMP(ip string, state *memory.Memory, output *logger.Logger) {
	if state.Current[ip].ICMPs+state.Previous[ip].ICMPs > MaxICMP {
		output.Write("[CRITICAL] ICMP Ping Flood détecté.", ip)
		state.Current[ip].ICMPs, state.Previous[ip].ICMPs = 0, 0
	}
}

func UDP(ip string, state *memory.Memory, output *logger.Logger) {
	if state.Current[ip].UDPs+state.Previous[ip].UDPs > MaxUDP {
		output.Write("[CRITICAL] UDP Flood détecté.", ip)
		state.Current[ip].UDPs, state.Previous[ip].UDPs = 0, 0
	}
	all, previous := state.Current["ALL"], state.Previous["ALL"]
	if all.DNSResponses+previous.DNSResponses-all.DNSRequests-previous.DNSRequests > MaxDNS {
		output.Write("[CRITICAL] Attaque DDoS par amplification DNS détectée.", "")
		all.DNSResponses, all.DNSRequests = 0, 0
	}
}

func ARP(ip, mac string, state *memory.Memory, output *logger.Logger) {
	if state.Current[ip].ARPMAC != "" && state.Current[ip].ARPMAC != mac {
		output.Write("[CRITICAL] ARP Spoofing/Poisoning possible.", ip)
	}
}
