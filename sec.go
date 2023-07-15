package main

import (
	//"bytes"
	//"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"net"
	//"strconv"
	//"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	iface    = "en0"
	snaplen  = int32(320)
	promisc  = true
	timeout  = pcap.BlockForever
	//filter   = "tcp[13] == 0x11 or tcp[13] == 0x10 or tcp[13] == 0x18"
	filter = "tcp and dst port 21"
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
	}
}

func main() {
	if len(os.Args) != 4 {
		log.Fatalln("Usage: main.go <capture_iface> <target_ip> <port1,port2,port3>")
	}
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Panicln(err)
	}
	iface := os.Args[1]
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

	ip := os.Args[2]
	go capture(iface, ip)
	time.Sleep(1 * time.Second)

	ports := strings.Split(os.Args[3], ",")
	fmt.Println(ports)

	for _, port := range ports {
		target := fmt.Sprintf("%s:%s", ip, port)
		fmt.Println("Trying", target)
		c, err := net.DialTimeout("tcp", target, 1000*time.Millisecond)
		if err != nil {
			continue
		}
		c.Close()
	}
	time.Sleep(2 * time.Second)

	for port, confidence := range results { 
		 if confidence >= 1 {
		fmt.Printf("Port %s open (confidence: %d)\n", port, confidence) }
		}
}
