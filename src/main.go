package main

import (
	"fmt"
	"log"
	"maps"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"ids/config"
	"ids/logger"
	"ids/memory"
	"ids/process"
)

func showLoading(frame int) {
	frames := []rune{'|', '/', '-', '\\'}
	fmt.Printf("\rIDS is monitoring traffic... %c", frames[frame%len(frames)])
}

func clearLoading() {
	fmt.Print("\r\033[K")
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("usage: sudo ./ids <interface name>")
		return
	}

	interfaceName := os.Args[1]
	myIP, err := config.InterfaceIP(interfaceName)
	if err != nil {
		log.Fatal(err)
	}
	whitelist, err := config.LoadWhitelist("./whitelist.txt")
	if err != nil {
		log.Fatal(err)
	}
	state := memory.New()

	if err := os.MkdirAll("./logs", 0755); err != nil {
		log.Fatal(err)
	}
	output, err := logger.New("./logs/ids.log")
	if err != nil {
		log.Fatal(err)
	}
	defer output.Close()

	handle, err := config.OpenLive(interfaceName, myIP, whitelist)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packets := make(chan gopacket.Packet, config.ChannelSize)
	source := gopacket.NewPacketSource(handle, layers.LinkTypeEthernet)
	source.NoCopy = true
	go config.StreamPackets(source, packets)

	ticker := time.NewTicker(config.Period * time.Second)
	defer ticker.Stop()
	loadingTicker := time.NewTicker(500 * time.Millisecond)
	defer loadingTicker.Stop()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)

	packetCount, totalPackets := 0, 0
	loadingFrame := 0
	showLoading(loadingFrame)
	for {
		memory.SeedARPCache(state)
		windowComplete := false
		for !windowComplete {
			select {
			case <-signals:
				clearLoading()
				output.Write(fmt.Sprintf("%d seconds summary: %d packets of %d", config.Period, packetCount, totalPackets), "")
				_ = output.Flush()
				return
			case <-loadingTicker.C:
				loadingFrame++
				showLoading(loadingFrame)
			case <-ticker.C:
				totalPackets += packetCount
				packetsPerSecond := float64(packetCount) / float64(config.Period)
				output.Write(fmt.Sprintf("%d seconds summary: %d packets of %d || %.2f packets per second", config.Period, packetCount, totalPackets, packetsPerSecond), "")
				state.Previous = maps.Clone(state.Current)
				state.Current = make(map[string]*memory.Info)
				memory.EnsureIP(state, "ALL")
				packetCount = 0
				windowComplete = true
			case packet := <-packets:
				packetCount++
				process.Packet(packet, state, myIP, output)
			}
		}
		_ = output.Flush()
	}
}
