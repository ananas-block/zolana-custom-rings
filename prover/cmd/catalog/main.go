// Command catalog prints the authoritative circuit shapes for host catalog generation.
package main

import (
	"encoding/json"
	"github.com/helius-labs/zolana-custom-rings/prover/ring"
	"os"
)

func main() {
	if err := json.NewEncoder(os.Stdout).Encode(ring.Keys); err != nil {
		panic(err)
	}
}
