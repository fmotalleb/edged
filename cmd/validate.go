package cmd

import (
	"fmt"

	"github.com/fmotalleb/go-tools/log"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/fmotalleb/edged/config"
)

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate configuration file syntax and structure, then exit",
	RunE: func(cmd *cobra.Command, _ []string) error {
		logger := log.FromContext(cmd.Context())
		logger.Info("Validating configuration file", zap.String("path", configPath))
		_, err := config.Load(cmd.Context(), configPath)
		if err != nil {
			return fmt.Errorf("configuration validation failed: %w", err)
		}
		fmt.Printf("Configuration file '%s' is valid!\n", configPath)
		return nil
	},
}
