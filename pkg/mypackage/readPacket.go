// pcap handling function
package mypackage

import(
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"fmt"
	"github.com/pterm/pterm"
	"github.com/google/gopacket/layers"
	"strconv"
	"os"
)

func Read(filename string) error {
	var num_packets int
	//Setting options
	var selectedPackets []gopacket.Packet
	options := []string{}


	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return err
	}
	defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	var packets []gopacket.Packet

	for packet := range packetSource.Packets() {
		packets = append(packets, packet)
	}
	fmt.Println(pterm.LightGreen("Total packets in the file: ", len(packets)))
	num_packets,_ = strconv.Atoi(os.Args[2])
	for i := 0; i < num_packets; i++ {
		var srcIP string
		var dstIP string
		var protocol string
		pterm.BgLightGreen.Println("Packet ", i+1) 
		//Network Layer
		fmt.Println("Network Layer  ")
		//pterm.Println(pterm.Red(packets[i].NetworkLayer()))
		networkLayer := packets[i].NetworkLayer()
		if networkLayer != nil {
			// Type assertion to get the IPv4 layer
			ipLayer, ok := networkLayer.(*layers.IPv4)
			if ok {
				fmt.Println(pterm.Red("Source IP: ", ipLayer.SrcIP))
				fmt.Println(pterm.Red("Destination IP: ", ipLayer.DstIP))
				srcIP = ipLayer.SrcIP.String()
				dstIP = ipLayer.DstIP.String()
			} else {
				fmt.Println("Not an IPv4 packet.")
			}
		} else {
			fmt.Println("No network layer found.")
		}
		//Transport Layer
		fmt.Println("Transport Layer")
		fmt.Print(pterm.Yellow("Protocol: "))
		transportLayer := packets[i].TransportLayer()
		if transportLayer != nil {
			switch transportLayer.LayerType() {
			case layers.LayerTypeTCP:
				protocol = "TCP"
				fmt.Println(pterm.Yellow("TCP"))
				tcpLayer, _ := transportLayer.(*layers.TCP)
				fmt.Println(pterm.Yellow("Checksum:", tcpLayer.Checksum))
				fmt.Println(pterm.Yellow("Source Port: ", tcpLayer.SrcPort))
				fmt.Println(pterm.Yellow("Destination Port: ", tcpLayer.DstPort))
				fmt.Println(pterm.Yellow("Flags:", tcpLayer.FIN, tcpLayer.SYN, tcpLayer.RST, tcpLayer.PSH, tcpLayer.ACK, tcpLayer.URG, tcpLayer.ECE, tcpLayer.CWR))
				//fmt.Println(pterm.Yellow("Data Length: ", len(tcpLayer.Payload)))
			case layers.LayerTypeUDP:
				protocol = "UDP"
				fmt.Println(pterm.Yellow("UDP"))
				udpLayer, _ := transportLayer.(*layers.UDP)
				fmt.Println(pterm.Yellow("Checksum: ", udpLayer.Checksum))
				fmt.Println(pterm.Yellow("Source Port: ", udpLayer.SrcPort))
				fmt.Println(pterm.Yellow("Destination Port: ", udpLayer.DstPort))
				//fmt.Println(pterm.Yellow("Data Length: ", len(udpLayer.Payload)))
			case layers.LayerTypeICMPv4:
				protocol = "ICMPv4"
				fmt.Println(pterm.Yellow("ICMPv4"))
			case layers.LayerTypeICMPv6:
				protocol = "ICMPv6"
				fmt.Println(pterm.Yellow("ICMPv6"))
			case layers.LayerTypeSCTP:
				protocol = "SCTP"
				fmt.Println(pterm.Yellow("SCTP"))
				sctpLayer, _ := transportLayer.(*layers.SCTP)
				fmt.Println(pterm.Yellow("Checksum:", sctpLayer.Checksum))
			case layers.LayerTypeDNS:
				protocol = "DNS"
				fmt.Println(pterm.Yellow("DNS"))
			default:
				protocol = "Unknown"
				fmt.Println(pterm.Yellow("Unknown"))
			}
		}

		//Application layers
		applicationLayer := packets[i].ApplicationLayer()
		size := packets[i].ApplicationLayer()
		if applicationLayer!= nil {
			fmt.Println("Application Layer")
			fmt.Println(pterm.LightBlue("Data Size: ",applicationLayer))
		}
		
		captureInfo := packets[i].Metadata()
		if captureInfo!= nil {
		fmt.Println("Capture Info:")
		fmt.Println(pterm.Green("Timestamp: ", captureInfo.Timestamp))
		fmt.Println(pterm.Green("Capture Length: ", captureInfo.CaptureLength))
		fmt.Println(pterm.Green("Truncated: ", captureInfo.Truncated))
		}
		//fmt.Println(pterm.LightRed(packets[i]))
		options = append(options, fmt.Sprintf("%d %s %s %s      %s", i+1, srcIP, dstIP, protocol, size))  
		selectedPackets = append(selectedPackets, packets[i])
	}
	// Interactive packet selection
	// for true {
	// 	displayPrompt := "No  SrcIP       DstIP         Protocol   Size"
	// 	result, _ := pterm.DefaultInteractiveSelect.
	// 		WithDefaultText(displayPrompt).
	// 		WithOptions(options).
	// 		Show()
	// 	op := strings.Split(result, " ")

	// 	if op[0] == "q" || op[0] == "Q" {
	// 		break // Exit loop if 'q' or 'Q' is pressed
	// 	}
	// 		selectedIndex, err := strconv.Atoi(op[0])
	// 		if err != nil {
	// 			return err
	// 		}
	// 		// Process the selected packet
	// 		selectedPacket := selectedPackets[selectedIndex-1]
	// 		fmt.Println(pterm.LightBlue("Packet", selectedPacket))
	// }

	return nil
}