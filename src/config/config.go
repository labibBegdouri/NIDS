package config

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const (
	Period      = 4
	ChannelSize = 10000
	ReadTimeout = 10 * time.Millisecond
	Snaplen     = 1600
	Promiscuous = true
)

func InterfaceIP(interfaceName string) (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, networkInterface := range interfaces {
		if networkInterface.Name != interfaceName {
			continue
		}
		addresses, err := networkInterface.Addrs()
		if err != nil {
			return "", err
		}
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err == nil && ip.To4() != nil {
				return ip.String(), nil
			}
		}
	}
	return "", fmt.Errorf("no IPv4 address found for interface %q", interfaceName)
}

func LoadWhitelist(path string) ([]string, error) {
	reader, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	whitelist := make([]string, 0)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" && line[0] != '#' {
			whitelist = append(whitelist, line)
		}
	}
	return whitelist, scanner.Err()
}

func OpenLive(interfaceName, myIP string, whitelist []string) (*pcap.Handle, error) {
	handle, err := pcap.OpenLive(interfaceName, Snaplen, Promiscuous, ReadTimeout)
	if err != nil {
		return nil, err
	}
	filter := fmt.Sprintf("not src host %s", myIP)
	for _, ip := range whitelist {
		filter += fmt.Sprintf(" and not src host %s", ip)
	}
	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return nil, err
	}
	return handle, nil
}

func StreamPackets(source *gopacket.PacketSource, packets chan<- gopacket.Packet) {
	for {
		packet, err := source.NextPacket()
		if err == io.EOF {
			return
		}
		if err == nil {
			packets <- packet
		}
	}
}
