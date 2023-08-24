package main

import (
	"github.com/gdamore/tcell/"
	"github.com/gdamore/tcell/v2/views"
)

func main() {
	tcell.SetEncodingFallback(tcell.EncodingFallbackASCII)
	screen, err := tcell.NewScreen()
	if err != nil {
		panic(err)
	}
	if err := screen.Init(); err != nil {
		panic(err)
	}
	defer screen.Fini()

	view := views.NewTextView()
	view.SetText("Hello, Tcell!")
	view.SetRect(0, 0, 20, 5)
	view.SetDynamicColors(true)

	app := &views.Application{}
	if err := app.SetRoot(view, true).Run(); err != nil {
		panic(err)
	}
}

