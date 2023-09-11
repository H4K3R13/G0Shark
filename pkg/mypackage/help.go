package mypackage

import (
	"fmt"
	"github.com/pterm/pterm"
)

// Option represents a command-line option with its function and example.
type Option struct {
	Command   string
	Function  string
	Example   string
}

// Help displays the available command-line options.
func Help() {
	options := []Option{
		{"-h", "Help", ""},
		{"-r", "Read .pcap files", "-r filename/filepath"},
		{"-s", "Scan an IP", "-s en0 $IP [port,port,port]or[port-port]"},
	}

	table := pterm.TableData{}
	table = append(table, []string{"Option", "Function", "Example"})

	for _, opt := range options {
		table = append(table, []string{opt.Command, opt.Function, opt.Example})
	}

	pterm.DefaultTable.WithHasHeader().WithBoxed().WithData(table).Render()
	fmt.Println("Select the packets from the option selector")
}
