package main

import (
	//"bytes"
	"fmt"
	"log"
	"os"
	//FOR TUI
	"github.com/pterm/pterm"
	//"github.com/gdamore/tcell"
	//"github.com/pterm/pterm/putils"
	"G0Shark/pkg/mypackage"
)


func main() {
	s,_ := pterm.DefaultBigText.WithLetters(pterm.NewLettersFromString("G0Shark")).Srender()
	pterm.DefaultCenter.Println(pterm.LightBlue(s))
	pterm.DefaultCenter.Println(("Develped By @H4K3R (Github)"))


	choice := os.Args[1]
	if choice == "-s" {
		mypackage.Scan()
	} else if choice == "-r" {
		//filename := "packet.pcap"
		filename := os.Args[3]
		//err := readPcapFile(filename)
		err := mypackage.Read(filename)
		if err != nil {
			log.Fatal(err)
		}
	}	else if choice == "-h"{
	mypackage.Help()
	}
}
