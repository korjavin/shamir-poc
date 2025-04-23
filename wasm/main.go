package main

import (
	"crypto/rand"
	"encoding/base64"
	"syscall/js"
)

// Global variables to prevent garbage collection of function values
var (
	generateRandomBytesFunc js.Func
)

func main() {
	// Create a channel to keep the program running
	c := make(chan struct{}, 0)

	// Initialize function values
	generateRandomBytesFunc = js.FuncOf(generateRandomBytes)

	// Register JavaScript functions
	js.Global().Set("goWasm", map[string]interface{}{
		"generateRandomBytes": generateRandomBytesFunc,
	})

	// Initialize crypto functions
	InitCryptoFunctions()

	// Print a message to the console
	js.Global().Get("console").Call("log", "WebAssembly module initialized")

	// Keep the program running
	<-c
}

// generateRandomBytes generates random bytes of the specified length
func generateRandomBytes(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return js.Error{Value: js.ValueOf("Missing length argument")}
	}

	length := args[0].Int()
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return js.Error{Value: js.ValueOf(err.Error())}
	}

	// Return base64url encoded string
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(bytes)
}
