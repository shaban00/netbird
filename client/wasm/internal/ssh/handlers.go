//go:build js

package ssh

import (
	"io"
	"syscall/js"

	"github.com/sirupsen/logrus"
)

// CreateJSInterface creates a JavaScript interface for the SSH client
func CreateJSInterface(client *Client) js.Value {
	jsInterface := js.Global().Get("Object").Call("create", js.Null())

	writeFunc := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 1 {
			return js.ValueOf(false)
		}

		data := args[0]
		var bytes []byte

		if data.Type() == js.TypeString {
			bytes = []byte(data.String())
		} else {
			uint8Array := js.Global().Get("Uint8Array").New(data)
			length := uint8Array.Get("length").Int()
			bytes = make([]byte, length)
			js.CopyBytesToGo(bytes, uint8Array)
		}

		_, err := client.Write(bytes)
		return js.ValueOf(err == nil)
	})
	jsInterface.Set("write", writeFunc)

	resizeFunc := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 2 {
			return js.ValueOf(false)
		}
		cols := args[0].Int()
		rows := args[1].Int()
		err := client.Resize(cols, rows)
		return js.ValueOf(err == nil)
	})
	jsInterface.Set("resize", resizeFunc)

	closeFunc := js.FuncOf(func(this js.Value, args []js.Value) any {
		client.Close()
		return js.Undefined()
	})
	jsInterface.Set("close", closeFunc)

	go func() {
		readLoop(client, jsInterface)
		// Detach before releasing so late JS calls surface as TypeError instead
		// of silent "call to released function".
		jsInterface.Set("write", js.Undefined())
		jsInterface.Set("resize", js.Undefined())
		jsInterface.Set("close", js.Undefined())
		writeFunc.Release()
		resizeFunc.Release()
		closeFunc.Release()
	}()

	return jsInterface
}

func readLoop(client *Client, jsInterface js.Value) {
	// The browser terminal can't receive SSH banners, so show the banner
	// (e.g. the recording notice) as the first output, formatted like displayBanner.
	if banner := client.Banner(); banner != "" {
		emitToJS(jsInterface, []byte(banner+"\r\n"))
	}

	buffer := make([]byte, 4096)
	for {
		n, err := client.Read(buffer)
		if err != nil {
			if err != io.EOF {
				logrus.Debugf("SSH read error: %v", err)
			}
			if onclose := jsInterface.Get("onclose"); !onclose.IsUndefined() {
				onclose.Invoke()
			}
			client.Close()
			return
		}

		emitToJS(jsInterface, buffer[:n])
	}
}

// emitToJS forwards data to the JS side's ondata callback, if one is attached.
func emitToJS(jsInterface js.Value, data []byte) {
	ondata := jsInterface.Get("ondata")
	if ondata.IsUndefined() {
		return
	}
	uint8Array := js.Global().Get("Uint8Array").New(len(data))
	js.CopyBytesToJS(uint8Array, data)
	ondata.Invoke(uint8Array)
}
