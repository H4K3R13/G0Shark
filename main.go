package main

import (
	//"bytes"
	"fmt"
	"log"
	"os"
	//"strings"
    "strconv"
	//FOR TUI
	"github.com/pterm/pterm"
	//"github.com/gdamore/tcell"
	//"github.com/pterm/pterm/putils"
	"G0Shark/pkg/mypackage"

	tea "github.com/charmbracelet/bubbletea"
)

func formatPacketData(packets []mypackage.PacketData, selected map[int]struct{}) []string {
    formatted := make([]string, len(packets))
    for i, packet := range packets {
        payload := ""
        if _, ok := selected[i]; ok {
             payload = fmt.Sprintf("%+v", packet)
        }
        formatted[i] = fmt.Sprintf("Source IP: %s, Destination IP: %s, Protocol: %s, Payload: %s", packet.SourceIP, packet.DestinationIP, packet.Protocol, payload)
    }
    return formatted
}


type model struct {
	packets []string
    cursor int
    selected map[int]struct{}
}

func initialModel(filename string, numPackets int) model {
    packetsData, err := mypackage.Read(filename, numPackets)
    if err != nil {
        log.Fatal(err)
    }
    selected := make(map[int]struct{})
    formattedPackets := formatPacketData(packetsData, selected)

    return model{
        packets:  formattedPackets,
        cursor:   0, 
        selected: selected, 
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
        case "enter", " ":
            // Clear all previous selections
            m.selected = make(map[int]struct{})
            
            // Select the current item
            m.selected[m.cursor] = struct{}{}
        }
    }
    return m, nil
}




func (m model) View() string {
    s := pterm.Green("Select A Packet\n")
    for i, packet := range m.packets {
        cursor := " " 
        if m.cursor == i {
            cursor = pterm.Blue(">") // cursor!
        }
        checked := " " 
        if _, ok := m.selected[i]; ok {
            checked = pterm.Red("x") // selected!
        }
        s += pterm.Sprintf("%s [%s] %s\n", cursor, checked, packet)
        // s += fmt.Sprintf("Destination IP: %s\n", packet.DestinationIP)
        // s += fmt.Sprintf("Protocol: %s\n", packet.Protocol)
        // Add more fields as needed
        s += "\n" // Separate packets with a blank line
    }
    s += pterm.Green("\nPress q to quit.\n")
    
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
        num_arg := os.Args[2]
        filename := os.Args[3]
        num, err := strconv.Atoi(num_arg)
        if err != nil {
            log.Fatalf("Failed to convert %s to an integer: %v", num, err)
        }
        program := tea.NewProgram(initialModel(filename,num))
        if err := program.Start(); err != nil {
            log.Fatal(err)
    }
	}	else if choice == "-h"{
	mypackage.Help()
	}
	

}
