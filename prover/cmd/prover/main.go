package main

import (
	"os"

	_ "github.com/helius-labs/zolana-custom-rings/prover/ring"
	"github.com/helius-labs/zolana/prover/server/app"
	"github.com/helius-labs/zolana/prover/server/logging"
)

func main() {
	if err := app.Run(os.Args); err != nil {
		logging.Logger().Fatal().Err(err).Msg("App failed.")
	}
}
