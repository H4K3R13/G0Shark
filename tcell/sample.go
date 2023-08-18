package main

import (
	"fmt"
	"log"

	//"time"

	"github.com/gdamore/tcell"
)

// Simulating a basic logMessage function for demonstration purposes.
func logMessage(msg string) {
	fmt.Println(msg)
}

func main() {
	// Initialize tcell screen
	screen, err := tcell.NewScreen()
	if err != nil {
		log.Fatal(err)
	}
	if err = screen.Init(); err != nil {
		log.Fatal(err)
	}
	defer screen.Fini()

	// Main event loop
	for {
		ev := screen.PollEvent()
		switch ev := ev.(type) {
		case *tcell.EventKey:
			mod, key, ch := ev.Modifiers(), ev.Key(), ev.Rune()
			logMessage(fmt.Sprintf("EventKey Modifiers: %d Key: %d Rune: %d", mod, key, ch))
		case *tcell.EventResize:
			// Handle resize event if needed
			logMessage("Resize event")
		case *tcell.EventInterrupt:
			// Handle interrupt event if needed
			logMessage("Interrupt event")
		default:
			logMessage("Unknown event")
		}
	}
}
