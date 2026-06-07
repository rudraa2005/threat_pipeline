// Paste this into a main.go and run it. Understand every line.
package main

import "fmt"

func main() {
	var word uint64 = 0

	// Set bit at position 5
	pos := uint(5)
	word |= (1 << pos)
	fmt.Printf("after setting bit 5: %064b\n", word)

	// Check bit at position 5
	isSet := (word & (1 << pos)) != 0
	fmt.Println("bit 5 is set:", isSet)

	// Check bit at position 3 (never set)
	isSet = (word & (1 << uint(3))) != 0
	fmt.Println("bit 3 is set:", isSet)

	// Which uint64 word holds bit position 130?
	bigPos := uint(130)
	wordIndex := bigPos / 64 // = 2
	bitIndex := bigPos % 64  // = 2
	fmt.Println("bit 130 lives in word", wordIndex, "at bit", bitIndex)
}
