package mypackage
import(
	"github.com/pterm/pterm"
	"fmt"
)
func Help(){
	pterm.DefaultTable.WithHasHeader().WithBoxed().WithData(pterm.TableData{
		{"Option", "Function", "Example"},
		{"-h", "help", ""},
		{"-r", "Read .pcap files", "-r filename/filepath"},
		{"-s", "Scan an IP", "-s en0 $IP [port,port,port]or[port-port] "},	
		
	}).Render()
	fmt.Println("Select the packets from the option selector")
}