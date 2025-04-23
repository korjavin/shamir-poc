package main

import (
	"syscall/js"
)

// Global variables to prevent garbage collection of function values
// (moved to crypto.go)

func main() {
	// Create a channel to keep the program running
	c := make(chan struct{}, 0)

	// Create a global object for WebAssembly functions
	js.Global().Set("goWasm", map[string]interface{}{})

	// Initialize crypto functions
	InitCryptoFunctions()

	// Print a message to the console
	js.Global().Get("console").Call("log", "WebAssembly module initialized")

	// Keep the program running
	<-c
}

// generateRandomBytes moved to crypto.go
