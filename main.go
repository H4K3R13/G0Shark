package main

import (
	//"bytes"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	//FOR TUI
	"github.com/pterm/pterm"
	//"github.com/gdamore/tcell"
	//"github.com/pterm/pterm/putils"
	"G0Shark/pkg/mypackage"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/rivo/tview"
)

func formatPacketData(packets []mypackage.PacketData) []string {
	formatted := make([]string, len(packets))
	for i, packet := range packets {
		formatted[i] = fmt.Sprintf("Source IP: %s, Destination IP: %s, Protocol: %s", packet.SourceIP, packet.DestinationIP, packet.Protocol)
	}
	return formatted
}

type model struct {
	packets  []string
	cursor   int
	selected map[int]struct{}
}

func initialModel(filename string, numPackets int) model {
	packetsData, err := mypackage.Read(filename, numPackets)
	if err != nil {
		log.Fatal(err)
	}
	formattedPackets := formatPacketData(packetsData)
	return model{
		packets: formattedPackets,
	}
}

func (m model) Init() tea.Cmd {
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
			m.selected = make(map[int]struct{})
			m.selected[m.cursor] = struct{}{}
		case "c":
			m.selected = make(map[int]struct{}) // To clear up the displayed deatial of selected packets
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
			checked = pterm.Red("x")
		}
		s += pterm.Sprintf("%s [%s] %s\n", cursor, checked, packet)
	}

	if len(m.selected) > 0 {
		s += "\nSelected Packet Details:\n"
		for i := range m.selected {
			if i >= 0 && i < len(m.packets) {
				// Capture the selected Packet from the mypackage.Display
				capture := mypackage.Display(os.Args[3], i)
				// Display captured output
				s += strings.Join(capture, "\n")
			}
		}
	}

	s += pterm.Green("\nPress q to quit.\t c to clear")

	return s
}

func main() {

	s, _ := pterm.DefaultBigText.WithLetters(pterm.NewLettersFromString("G0Shark")).Srender()
	pterm.DefaultCenter.Println(pterm.LightBlue(s))
	pterm.DefaultCenter.Println(("Develped By @H4K3R (Github)"))
	choice := os.Args[1]

	app := tview.NewApplication()
	textView := tview.NewTextView().
		SetDynamicColors(true) 
	textView.SetTextAlign(tview.AlignCenter)
	textView.SetText("G0Shark")
	if err := app.SetRoot(textView, true).Run(); err != nil {
		panic(err)
	}

	if choice == "-s" {
		mypackage.Scan()
	} else if choice == "-r" {
		num_arg := os.Args[2]
		filename := os.Args[3]
		num, err := strconv.Atoi(num_arg)
		if err != nil {
			log.Fatalf("Failed to convert %s to an integer: %v")
		}
		program := tea.NewProgram(initialModel(filename, num))
		if err := program.Start(); err != nil {
			log.Fatal(err)
		}
	} else if choice == "-h" {
		mypackage.Help()
	}

}
