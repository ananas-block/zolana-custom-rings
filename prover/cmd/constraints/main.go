package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/logger"
	"github.com/helius-labs/zolana-custom-rings/prover/ring"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

type measurement struct {
	Circuit      common.CircuitType `json:"circuit"`
	Constraints  int                `json:"constraints"`
	PublicInputs int                `json:"publicInputs"`
	Commitments  int                `json:"commitments"`
	R1CSSHA256   string             `json:"r1csSha256"`
}

func main() {
	prefix := flag.String("prefix", "custom-ring-policy-", "circuit name prefix")
	flag.Parse()
	logger.Disable()
	keys := slices.DeleteFunc(slices.Clone(ring.Keys), func(k ring.Key) bool {
		return !strings.HasPrefix(string(k.Circuit), *prefix)
	})
	if err := writeCounts(os.Stdout, keys); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func writeCounts(output io.Writer, keys []ring.Key) error {
	if len(keys) == 0 {
		return fmt.Errorf("no matching circuits")
	}
	encoder := json.NewEncoder(output)
	for _, key := range keys {
		row, err := measure(key.Circuit)
		if err != nil {
			return err
		}
		if err := encoder.Encode(row); err != nil {
			return err
		}
	}
	return nil
}

func measure(name common.CircuitType) (measurement, error) {
	extension, ok := common.LookupExtension(name)
	if !ok {
		return measurement{}, fmt.Errorf("unknown circuit %q", name)
	}
	cs, err := extension.R1CS()
	if err != nil {
		return measurement{}, err
	}
	digest := sha256.New()
	if _, err := cs.WriteTo(digest); err != nil {
		return measurement{}, err
	}
	commitments, ok := cs.GetCommitments().(constraint.Groth16Commitments)
	if !ok {
		return measurement{}, fmt.Errorf("unsupported commitment format for %s", name)
	}
	return measurement{
		Circuit: name, Constraints: cs.GetNbConstraints(), PublicInputs: cs.GetNbPublicVariables() - 1,
		Commitments: len(commitments), R1CSSHA256: hex.EncodeToString(digest.Sum(nil)),
	}, nil
}
