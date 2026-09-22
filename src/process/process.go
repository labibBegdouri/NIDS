package process

import (
	"ids/logger"
	"ids/memory"
	"ids/update"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func Packet(packet gopacket.Packet, state *memory.Memory, myIP string, output *logger.Logger) {
	if packet.Layer(layers.LayerTypeIPv4) == nil && packet.Layer(layers.LayerTypeARP) == nil {
		return
	}
	update.Packet(packet, state, myIP, output)
}
