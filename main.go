package main

import (
	//"bytes"
	//"fmt"
	"log"
	"os"
	//FOR TUI
	"github.com/pterm/pterm"
	//"github.com/gdamore/tcell"
	//"github.com/pterm/pterm/putils"
	"G0Shark/pkg/mypackage"
	tea "github.com/charmbracelet/bubbletea"
)

type model struct {
    choice string
}

func (m model) Init() tea.Cmd {
    return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
    switch msg.(type) {
    case tea.KeyMsg:
        return m, tea.Quit
    }
    return m, nil
}

func (m model) View() string {
    // Your existing view code here
    // ...
	s := "Press q to quit"
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
		err := mypackage.Read(filename)
		if err != nil {
			log.Fatal(err)
		}
	}	else if choice == "-h"{
	mypackage.Help()
	}

	program := tea.NewProgram(model{})
    if err := program.Start(); err != nil {
        log.Fatal(err)
    }
}
