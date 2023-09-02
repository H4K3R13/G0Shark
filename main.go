package main

import (
	//"bytes"
	"fmt"
	"log"
	"os"
	//"strings"

	//FOR TUI
	"github.com/pterm/pterm"
	//"github.com/gdamore/tcell"
	//"github.com/pterm/pterm/putils"
	"G0Shark/pkg/mypackage"

	tea "github.com/charmbracelet/bubbletea"
)

func formatPacketData(packets []mypackage.PacketData) []string {
    formatted := make([]string, len(packets))
    for i, packet := range packets {
        // Format each packet data entry as a string
        formatted[i] = fmt.Sprintf("Source IP: %s, Destination IP: %s, Protocol: %s", packet.SourceIP, packet.DestinationIP, packet.Protocol)
        // You can add more fields if needed
    }
    return formatted
}


type model struct {
    selected map[int]struct{}
	packets []string
	choices []string
	cursor int
}

func initialModel() model {
	packetsData, err := mypackage.Read("packet.pcap", 4)
    if err != nil {
        log.Fatal(err)
    }
	formattedPackets := formatPacketData(packetsData)

    return model{
		packets: formattedPackets,
		selected: make(map[int]struct{}),
	}
}

func (m model) Init() tea.Cmd{
    return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
    switch msg := msg.(type) {
    case tea.KeyMsg:
        switch msg.String() {
        case "ctrl+c", "q":
            return m, tea.Quit
        case "up", "k":
            if m.cursor > 0 {
                m.cursor--
            }
        case "down", "j":
            if m.cursor < len(m.packets)-1 {
                m.cursor++
            }
        }
    }
    return m, nil
}


func (m model) View() string {
    s := "Press q to quit\n"

    for i, packet := range m.packets {
        s += fmt.Sprintf("Packet %d:\n", i+1)
        s += fmt.Sprintf("Source IP: %s\n", packet)
        // s += fmt.Sprintf("Destination IP: %s\n", packet.DestinationIP)
        // s += fmt.Sprintf("Protocol: %s\n", packet.Protocol)
        // Add more fields as needed
        s += "\n" // Separate packets with a blank line
    }

    return s
}




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
		packetsData, err := mypackage.Read(filename,3)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(packetsData)
	}	else if choice == "-h"{
	mypackage.Help()
	}
	

	program := tea.NewProgram(model{})
    if err := program.Start(); err != nil {
        log.Fatal(err)
    }
}
