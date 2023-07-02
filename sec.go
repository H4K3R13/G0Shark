package main

import(
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var(
	iface = "en"
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

	for _, device := range devices{
		if device.Name == iface{
			devFound = true
			fmt.Println("Device Found!!")
		}
	}

	if !devFound {
		log.Panicln("Device %s is not found !!", iface)
	}
	
} 