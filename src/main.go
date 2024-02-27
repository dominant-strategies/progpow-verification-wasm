package main

import (
	"fmt"

	"github.com/dominant-strategies/progpow-verification-wasm/progpow"
	"github.com/dominant-strategies/progpow-verification-wasm/types"
)

func main() {
	// Initialize a Progpow instance
	// Note: This example assumes Progpow doesn't require special initialization.
	// You might need to provide configuration or other dependencies here.
	progpowInstance := progpow.Progpow{}

	// Create a types.Header instance for demonstration purposes
	// You'll need to fill this with actual data relevant to your application
	header := &types.Header{
		// Populate the fields as necessary
	}

	// Call VerifySeal
	powHash, err := progpowInstance.VerifySeal(header)
	if err != nil {
		fmt.Println("VerifySeal error:", err)
	} else {
		fmt.Println("VerifySeal success, powHash:", powHash)
	}

	// Call ComputePowLight
	mixHash, powHash := progpowInstance.ComputePowLight(header)
	fmt.Println("ComputePowLight success, mixHash:", mixHash, "powHash:", powHash)
}
