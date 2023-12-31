// pcap handling function
package mypackage

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	//"fmt"
	"github.com/google/gopacket/layers"
	"github.com/pterm/pterm"
	"os"
	"strconv"
)

type PacketData struct {
	SourceIP      string
	DestinationIP string
	Protocol      string
	payload       string
	// Add other fields you want to include
}

func Read(filename string, numPackets int) ([]PacketData, error) {
	var packetsData []PacketData
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetCount := 0

	for packet := range packetSource.Packets() {
		if packetCount >= numPackets {
			break
		}
		var packetInfo PacketData
		packetInfo.payload = fmt.Sprintf("%s", packet)
		networkLayer := packet.NetworkLayer()
		if networkLayer != nil {
			ipLayer, ok := networkLayer.(*layers.IPv4)
			if ok {
				packetInfo.SourceIP = ipLayer.SrcIP.String()
				packetInfo.DestinationIP = ipLayer.DstIP.String()
			}
		}
		transportLayer := packet.TransportLayer()
		if transportLayer != nil {
			switch transportLayer.LayerType() {
			case layers.LayerTypeTCP:
				packetInfo.Protocol = "TCP"
			case layers.LayerTypeUDP:
				packetInfo.Protocol = "UDP"
			case layers.LayerTypeICMPv4:
				packetInfo.Protocol = "ICMPv4"
			}
		}
		packetsData = append(packetsData, packetInfo)
		packetCount++
	}
	return packetsData, nil
}


func Display(filename string, index int) []string {
	var num_packets int
	var packet []string 
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		fmt.Println(err)
	}
	defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	var packets []gopacket.Packet

	for packet := range packetSource.Packets() {
		packets = append(packets, packet)
	}
	//fmt.Println(pterm.LightGreen("Total packets in the file: ", len(packets)))
	num_packets, _ = strconv.Atoi(os.Args[2])
	for i := 0; i < num_packets; i++ {
		if i == index {
			//pterm.BgLightGreen.Println("Packet ", i+1)
			//Network Layer
			packet = append(packet, pterm.Sprintf(pterm.Blue("Network Layer")))
			//fmt.Println("Network Layer  ")
			//pterm.Println(pterm.Red(packets[i].NetworkLayer()))
			networkLayer := packets[i].NetworkLayer()
			if networkLayer != nil {
				// Type assertion to get the IPv4 layer
				ipLayer, ok := networkLayer.(*layers.IPv4)
				if ok {
					packet = append(packet, pterm.Sprintf(pterm.LightRed("Source IP: ", ipLayer.SrcIP)))
					packet = append(packet, pterm.Sprintf(pterm.LightRed("Destination IP: ", ipLayer.DstIP)))
					//fmt.Println(pterm.Red("Source IP: ", ipLayer.SrcIP))
					//fmt.Println(pterm.Red("Destination IP: ", ipLayer.DstIP))
				} else {
					packet = append(packet, pterm.Sprintf(pterm.LightRed("Not an IPv4 packet")))
					//fmt.Println("Not an IPv4 packet.")
				}
			} else {
				packet = append(packet, pterm.Sprintf(pterm.LightRed("No Network Layer Found")))
				//fmt.Println("No network layer found.")
			}
			//Transport Layer
			packet = append(packet, pterm.Sprintf(pterm.Blue("Transport Layer")))
			//fmt.Println("Transport Layer")
			transportLayer := packets[i].TransportLayer()
			if transportLayer != nil {
				switch transportLayer.LayerType() {
				case layers.LayerTypeTCP:
					packet = append(packet, pterm.Sprintf(pterm.LightYellow("Protocol: TCP")))
					//fmt.Println(pterm.Yellow("TCP"))
					tcpLayer, _ := transportLayer.(*layers.TCP)
					packet = append(packet, pterm.Sprintf(pterm.LightYellow("Checksum: ", tcpLayer.Checksum)))
					//fmt.Println(pterm.Yellow("Checksum:", tcpLayer.Checksum))
					packet = append(packet, pterm.Sprintf(pterm.LightYellow("Destination Port: ", tcpLayer.DstPort)))
					//fmt.Println(pterm.Yellow("Source Port: ", tcpLayer.SrcPort))
					packet = append(packet, pterm.Sprintf(pterm.LightYellow("Source Port: ", tcpLayer.SrcPort)))
					//fmt.Println(pterm.Yellow("Destination Port: ", tcpLayer.DstPort))
					//packet = append(packet, fmt.Sprintf("Flags: %b", tcpLayer.FIN, tcpLayer.SYN, tcpLayer.RST, tcpLayer.PSH, tcpLayer.ACK, tcpLayer.URG, tcpLayer.ECE, tcpLayer.CWR))
					//fmt.Println(pterm.Yellow("Flags:", tcpLayer.FIN, tcpLayer.SYN, tcpLayer.RST, tcpLayer.PSH, tcpLayer.ACK, tcpLayer.URG, tcpLayer.ECE, tcpLayer.CWR))
					packet = append(packet, pterm.Sprintf(pterm.LightYellow("Data Length: ", len(tcpLayer.Payload))))
					//fmt.Println(pterm.Yellow("Data Length: ", len(tcpLayer.Payload)))
				case layers.LayerTypeUDP:
					packet = append(packet, pterm.Sprintf(pterm.LightYellow("Protocol: UDP")))
					//fmt.Println(pterm.Yellow("UDP"))
					udpLayer, _ := transportLayer.(*layers.UDP)
					packet = append(packet, pterm.Sprintf(pterm.LightYellow("Checksum: ", udpLayer.Checksum)))
					//fmt.Println(pterm.Yellow("Checksum: ", udpLayer.Checksum))
					packet = append(packet, pterm.Sprintf(pterm.LightYellow("Source Port: ", udpLayer.SrcPort)))
					//fmt.Println(pterm.Yellow("Source Port: ", udpLayer.SrcPort))
					packet = append(packet, pterm.Sprintf(pterm.LightYellow("Destination Port: ", udpLayer.DstPort)))
					//fmt.Println(pterm.Yellow("Destination Port: ", udpLayer.DstPort))
					packet = append(packet, pterm.Sprintf(pterm.LightYellow("Data Length: ", len(udpLayer.Payload))))
					//fmt.Println(pterm.Yellow("Data Length: ", len(udpLayer.Payload)))
				case layers.LayerTypeICMPv4:
					packet = append(packet, pterm.Sprintf(pterm.LightYellow("Protocol: ICMPv4")))
					//fmt.Println(pterm.Yellow("ICMPv4"))
				case layers.LayerTypeICMPv6:
					packet = append(packet, pterm.Sprintf(pterm.LightYellow("Protocol: ICMPv6")))
					//fmt.Println(pterm.Yellow("ICMPv6"))
				case layers.LayerTypeSCTP:
					packet = append(packet, pterm.Sprintf(pterm.LightYellow("Protocol: SCTP")))
					//fmt.Println(pterm.Yellow("SCTP"))
					sctpLayer, _ := transportLayer.(*layers.SCTP)
					packet = append(packet, pterm.Sprintf(pterm.LightYellow("Checksum: %d", sctpLayer.Checksum)))
					//fmt.Println(pterm.Yellow("Checksum:", sctpLayer.Checksum))
				case layers.LayerTypeDNS:
					packet = append(packet, pterm.Sprintf(pterm.LightYellow("Protocol: DNS")))
					//fmt.Println(pterm.Yellow("DNS"))
				default:
					packet = append(packet, pterm.Sprintf(pterm.LightYellow("Unknown")))
					//fmt.Println(pterm.Yellow("Unknown"))
				}
			}

			//Application layers
			applicationLayer := packets[i].ApplicationLayer()
			if applicationLayer != nil {
				packet = append(packet, pterm.Sprintf(pterm.Blue("Application Layer")))
				//fmt.Println("Application Layer")
				packet = append(packet, fmt.Sprintf("Data Size: %s", applicationLayer))
				//fmt.Println(pterm.LightBlue("Data Size: ", applicationLayer))
			}

			captureInfo := packets[i].Metadata()
			if captureInfo != nil {
				packet = append(packet, fmt.Sprintf("Capture Info: "))
				//fmt.Println("Capture Info:")
				packet = append(packet, fmt.Sprintf("Timestamp %s", captureInfo.Timestamp))
				//fmt.Println(pterm.Green("Timestamp: ", captureInfo.Timestamp))
				packet = append(packet, fmt.Sprintf("Capture Length: %d", captureInfo.CaptureLength))
				//fmt.Println(pterm.Green("Capture Length: ", captureInfo.CaptureLength))
				packet = append(packet, fmt.Sprintf("Truncated: %t", captureInfo.Truncated))
				//fmt.Println(pterm.Green("Truncated: ", captureInfo.Truncated))
			}
			packet = append(packet, pterm.Sprintf(pterm.LightCyan(packets[i])))
		}
	}
	return packet
}
