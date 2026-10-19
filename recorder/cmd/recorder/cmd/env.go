package cmd

import (
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func setFlagsFromEnvVars(cmd *cobra.Command) {
	flags := cmd.PersistentFlags()
	flags.VisitAll(func(f *pflag.Flag) {
		envVar := flagNameToEnvVar(f.Name, "NB_")
		value, present := os.LookupEnv(envVar)
		if !present {
			return
		}
		if err := flags.Set(f.Name, value); err != nil {
			log.Infof("unable to configure flag %s using variable %s, err: %v", f.Name, envVar, err)
		}
	})
}

func flagNameToEnvVar(cmdFlag string, prefix string) string {
	parsed := strings.ReplaceAll(cmdFlag, "-", "_")
	upper := strings.ToUpper(parsed)
	return prefix + upper
}
