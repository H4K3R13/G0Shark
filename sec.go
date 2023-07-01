package main

import(
	"fmt"
	"log"

	"github.com/google/gopacket/pcap"
)

func main(){
	devices, err := pcap.FindAllDevs()

	if err != nil {
		log.Panicln(err)
	}

	for _, devices := range devices {
		fmt.Println(devices.Name)
		
		for _,address := range devices.Addresses{
			fmt.Println("IP:", address.IP)
			fmt.Println("NetMask", address.Netmask)
		}
	}

} 