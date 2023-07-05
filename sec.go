package main

import(
	"encoding/hex"
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var(
	iface = "en0"
	snaplen = int32(1600)
	promisc = false
	timeout = pcap.BlockForever
	filter = "tcp and port 80"
	devFound = false
)

func main(){
	devices, err := pcap.FindAllDevs()

	if err != nil {
		log.Panicln(err)
	}

	fmt.Println("Printing All Network Interfaces")
	for _, devices := range devices {
		fmt.Println(devices.Name)
		
		for _,address := range devices.Addresses{
			fmt.Println("IP:", address.IP)
			fmt.Println("NetMask", address.Netmask)
		}
	}

	fmt.Println("Enter the Device Name")
	fmt.Scanln(&iface)

	for _, device := range devices{
		if device.Name == iface{
			devFound = true
			fmt.Println("Device Found!!")
		}
	}

	if !devFound {
		log.Panicf("Device '%s' is not found !!\n", iface)
	}
	
	handle, err := pcap.OpenLive(iface, snaplen, promisc, timeout)
	if err != nil {
		log.Panicln(err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(filter); err!= nil{
		log.Panicln(err)
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType()) 
	for packet := range source.Packets(){
		fmt.Println("Packets:",packet) 
		// Get the application layer (payload) of the packet
		appLayer := packet.ApplicationLayer()
		if appLayer != nil {
			fmt.Println("Application Layer/Payload:")
			fmt.Printf("%s\n", appLayer.Payload())
		}
		// Get the packet data in hex dump format
		fmt.Println("Packet Data (Hex Dump):")
		fmt.Printf("%s\n", hex.Dump(packet.Data()))
	
	}
		
} 