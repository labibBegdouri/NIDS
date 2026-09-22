package update

import (
	"ids/detect"
	"ids/logger"
	"ids/memory"
	"slices"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func Packet(packet gopacket.Packet, state *memory.Memory, myIP string, output *logger.Logger) {
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		ipAddress := ip.SrcIP.String()
		memory.EnsureIP(state, ipAddress)
		memory.EnsureIP(state, "ALL")
		if _, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP); ok {
			UDP(ipAddress, state, packet, myIP)
			detect.UDP(ipAddress, state, output)
			return
		}
		if ipAddress != myIP {
			if tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
				TCP(ipAddress, state, tcp)
				detect.TCP(ipAddress, state, output)
				return
			}
			if _, ok := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4); ok {
				state.Current[ipAddress].ICMPs++
				detect.ICMP(ipAddress, state, output)
				return
			}
		}
	}
	if arp, ok := packet.Layer(layers.LayerTypeARP).(*layers.ARP); ok && arp.Operation == 2 {
		ipAddress := AddrbyteToString(arp.SourceProtAddress, 10)
		if ipAddress == myIP {
			return
		}
		memory.EnsureIP(state, ipAddress)
		mac := AddrbyteToString(arp.SourceHwAddress, 16)
		detect.ARP(ipAddress, mac, state, output)
		state.Current[ipAddress].ARPMAC = mac
	}
}

func TCP(ip string, state *memory.Memory, tcp *layers.TCP) {
	info := state.Current[ip]
	if tcp.SYN {
		info.SYNs++
		if tcp.ACK {
			info.ACKs++
		}
	}
	if tcp.DstPort == 22 {
		info.SSHConnections++
	}
	if !slices.Contains(info.Ports, tcp.DstPort) && !slices.Contains(state.Previous[ip].Ports, tcp.DstPort) {
		info.Ports = append(info.Ports, tcp.DstPort)
		info.DistinctPorts++
	}
	if tcp.FIN {
		info.FINs++
	}
	if !tcp.ACK && !tcp.SYN && !tcp.RST && !tcp.ECE && !tcp.URG && !tcp.PSH {
		info.NullPackets++
	}
	if tcp.FIN && tcp.URG && tcp.PSH {
		info.XMASPackets++
	}
}

func UDP(ip string, state *memory.Memory, packet gopacket.Packet, myIP string) {
	info := state.Current[ip]
	info.UDPs++
	if dns, ok := packet.Layer(layers.LayerTypeDNS).(*layers.DNS); ok {
		if ip == myIP {
			info.DNSRequests++
			state.Current["ALL"].DNSRequests++
		} else if len(dns.Answers) != 0 {
			info.DNSResponses++
			state.Current["ALL"].DNSResponses++
		}
	}
}
