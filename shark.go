package main

import (
	//"bytes"
	"encoding/hex"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
	//FOR TUI
	"github.com/pterm/pterm"
	"github.com/google/gopacket/layers"
	"github.com/olekukonko/tablewriter"
	//"github.com/pterm/pterm/putils"
)

var (
	iface   = "en0"
	snaplen = int32(320)
	promisc = true
	timeout = pcap.BlockForever
	//filter   = "tcp[13] == 0x11 or tcp[13] == 0x10 or tcp[13] == 0x18"
	filter   = "tcp"
	devFound = false
	results  = make(map[string]int)
)

func capture(iface, target string) {
	handle, err := pcap.OpenLive(iface, snaplen, promisc, timeout)
	if err != nil {
		log.Panicln(err)
	}
	defer handle.Close()
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Panicln(err)
	}
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	fmt.Println("Capturing packets")
	for packet := range source.Packets() {
		networkLayer := packet.NetworkLayer()
		if networkLayer == nil {
			continue
		}
		transportLayer := packet.TransportLayer()
		if transportLayer == nil {
			continue
		}
		srcHost := networkLayer.NetworkFlow().Src().String()
		srcPort := transportLayer.TransportFlow().Src().String()
		if srcHost != target {
			continue
		}
		results[srcPort] += 1

		pterm.DefaultBasicText.Println(packet)

		// Get the application layer (payload) of the packet
		appLayer := packet.ApplicationLayer()
		if appLayer != nil {
			pterm.DefaultBasicText.Println("Application Layer/Payload:")
			pterm.DefaultBasicText.Println(appLayer.Payload())
		}

		// Get the packet data in hex dump format
		pterm.DefaultBasicText.Println("Packet Data (Hex Dump):")
		pterm.DefaultBasicText.Println(pterm.Gray(hex.Dump(packet.Data())))

	}
}



// To check port input
func parsePortRange(portRange string) ([]int, error) {
	var ports []int

	//to list 80-100 type of ports
	if strings.Contains(portRange, "-") {
		rangeParts := strings.Split(portRange, "-")
		start, err := strconv.Atoi(rangeParts[0])
		if err != nil {
			return nil, fmt.Errorf("invalid port number: %s", rangeParts[0])
		}
		end, err := strconv.Atoi(rangeParts[1])
		for port := start; port <= end; port++ {
			ports = append(ports, port)
		}
	}

	if strings.Contains(portRange, ",") {
		portStrings := strings.Split(portRange, ",")
		for _, portStr := range portStrings {
			port, err := strconv.Atoi(portStr)
			if err != nil {
				return nil, fmt.Errorf("invalid port number: %s", portStr)
			}
			ports = append(ports, port)
		}
	}

	return ports, nil

}

// pcap handling function
func readPcapFile(filename string) error {
	var num_packets int
	//Initialze the table
	table := tablewriter.NewWriter(os.Stdout)
	//Table header
	table.SetHeader([]string{"No.", "Src. IP"})
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
				table.Append([]string{strconv.Itoa(i+1),ipLayer.SrcIP.String()})
        		//table.Append([]string{"Destination IP", ipLayer.DstIP.String()})
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
				fmt.Println(pterm.Yellow("TCP"))
				tcpLayer, _ := transportLayer.(*layers.TCP)
				fmt.Println(pterm.Yellow("Checksum:", tcpLayer.Checksum))
				fmt.Println(pterm.Yellow("Source Port: ", tcpLayer.SrcPort))
				fmt.Println(pterm.Yellow("Destination Port: ", tcpLayer.DstPort))
				fmt.Println(pterm.Yellow("Flags:", tcpLayer.FIN, tcpLayer.SYN, tcpLayer.RST, tcpLayer.PSH, tcpLayer.ACK, tcpLayer.URG, tcpLayer.ECE, tcpLayer.CWR))
				//fmt.Println(pterm.Yellow("Data Length: ", len(tcpLayer.Payload)))
			case layers.LayerTypeUDP:
				fmt.Println(pterm.Yellow("UDP"))
				udpLayer, _ := transportLayer.(*layers.UDP)
				fmt.Println(pterm.Yellow("Checksum: ", udpLayer.Checksum))
				fmt.Println(pterm.Yellow("Source Port: ", udpLayer.SrcPort))
				fmt.Println(pterm.Yellow("Destination Port: ", udpLayer.DstPort))
				//fmt.Println(pterm.Yellow("Data Length: ", len(udpLayer.Payload)))
			case layers.LayerTypeICMPv4:
				fmt.Println(pterm.Yellow("ICMPv4"))
			case layers.LayerTypeICMPv6:
				fmt.Println(pterm.Yellow("ICMPv6"))
			case layers.LayerTypeSCTP:
				fmt.Println(pterm.Yellow("SCTP"))
				sctpLayer, _ := transportLayer.(*layers.SCTP)
				fmt.Println(pterm.Yellow("Checksum:", sctpLayer.Checksum))
			case layers.LayerTypeDNS:
				fmt.Println(pterm.Yellow("DNS"))
			default:
				fmt.Println(pterm.Yellow("Unknown"))
			}
		}

		//Application layers
		applicationLayer := packets[i].ApplicationLayer()
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

		fmt.Println(pterm.LightRed(packets[i]))
	}
	table.Render()
	return nil
}

//Service finder
func getServiceName(port string) string {
	serviceNames := map[string]string{
		"80":    "HTTP",
		"443":   "HTTPS",
		"8080":  "HTTP Proxy",
		"21":    "FTP",
	}

	service := serviceNames[port]
	return service

}

func scan() {
	if len(os.Args) != 5 {
		log.Fatalln("Usage: main.go <capture_iface> <target_ip> <port1,port2,port3>")
	}
	pterm.DefaultCenter.Print("Scanning", os.Args[3])
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Panicln(err)
	}

	iface := os.Args[2]
	for _, device := range devices {
		if device.Name == iface {
			devFound = true
		}
	}

	if !devFound {
		log.Panicf("Device named '%s' does not exist\n", iface)
	}
	if devFound == true {
		log.Printf("Device Found '%s", iface)
	}

	ip := os.Args[3]
	go capture(iface, ip)
	time.Sleep(1 * time.Second)

	//ports := strings.Split(os.Args[4], ",")
	portRange := os.Args[4]
	ports, err := parsePortRange(portRange)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println(ports)
	totalSteps := len(ports)
	progressbar, _ := pterm.DefaultProgressbar.WithTotal(totalSteps).Start()
	for _, port := range ports {
		progressbar.Increment()
		target := fmt.Sprintf("%s:%d", ip, port)
		pterm.DefaultBasicText.Println(pterm.Red("\nTrying: ", target))
		c, err := net.DialTimeout("tcp", target, 1000*time.Millisecond)
		if err != nil {
			continue
		}
		c.Close()
	}

	time.Sleep(2 * time.Second)
	for port, confidence := range results {
		if confidence >= 1 {
			serviceName := getServiceName(port)
			fmt.Printf("Port %s open (confidence: %d)\n  Servivce : %s \n", port, confidence, serviceName)
		}
	}
}

//Help Guide
func help(){
	pterm.DefaultTable.WithHasHeader().WithBoxed().WithData(pterm.TableData{
		{"Option", "Function", "Example"},
		{"-h", "help", ""},
		{"-r", "Read .pcap files", "-r filename/filepath"},
		{"-s", "Scan an IP", "-s en0 $IP [port,port,port]or[port-port] "},	
	}).Render()

}


func main() {
	s,_ := pterm.DefaultBigText.WithLetters(pterm.NewLettersFromString("G0Shark")).Srender()
	pterm.DefaultCenter.Println(pterm.LightBlue(s))
	pterm.DefaultCenter.Println(("Develped By @H4K3R (Github)"))

	choice := os.Args[1]
	if choice == "-s" {
		scan()
	} else if choice == "-r" {
		//filename := "packet.pcap"
		filename := os.Args[3]
		err := readPcapFile(filename)
		if err != nil {
			log.Fatal(err)
		}
	}	else if choice == "-h"{
		help()
	}
}
