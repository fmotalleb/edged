package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fmotalleb/go-tools/log"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/fmotalleb/edged/acme"
	"github.com/fmotalleb/edged/config"
	"github.com/fmotalleb/edged/proxy"
)

var (
	configPath string
	testConfig bool
	verbose    bool
)

var rootCmd = &cobra.Command{
	Use:   "edged",
	Short: "Golang Reverse Proxy with ACME TLS & DNS-01 Wildcard Support",
	Long: `edged is a high-performance Golang reverse proxy that provides automated TLS handling
via Let's Encrypt (ACME v2), comprehensive SOCKS5 proxy tunneling across all layers, and
first-class integration with ArvanCloud and Cloudflare for wildcard certificate generation.`,
	PersistentPreRun: func(_ *cobra.Command, _ []string) {
		if verbose {
			log.SetDebugDefaults()
		}
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		return runServer(ctx)
	},
}

func Execute() {
	rootCmd.AddCommand(validateCmd)
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runServer(ctx context.Context) error {
	ctx = log.WithNewEnvLoggerForced(ctx)
	logger := log.Of(ctx)
	logger.Info("Initializing edged reverse proxy server...", zap.String("config", configPath))

	cfg, err := config.Load(ctx, configPath)
	if err != nil {
		logger.Fatal("Fatal configuration error", zap.Error(err))
		return err
	}

	if testConfig {
		fmt.Printf("Configuration file '%s' is valid!\n", configPath)
		return nil
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Initialize ACME Let's Encrypt Manager if ACME TLS is configured
	var acmeMgr *acme.Manager
	acmeDomains := cfg.GetAllACMEDomains()
	if len(acmeDomains) > 0 {
		logger.Info("Initializing ACME Let's Encrypt Manager", zap.Strings("domains", acmeDomains))
		acmeMgr, err = acme.NewManager(ctx, cfg.ACME)
		if err != nil {
			logger.Fatal("Failed to initialize ACME Manager", zap.Error(err))
			return err
		}

		// Ensure all required certificates are present or obtain them via DNS-01 / HTTP-01
		logger.Info("Verifying TLS certificates for configured domains...")
		if err := acmeMgr.EnsureDomains(ctx, acmeDomains); err != nil {
			logger.Warn("Warning during certificate verification/acquisition", zap.Error(err))
			logger.Info("Note: The server will continue booting and attempt on-demand acquisition during TLS handshakes.")
		}

		// Start background certificate renewal loop
		acmeMgr.StartRenewalDaemon(ctx, acmeDomains)
	} else {
		logger.Info("No ACME TLS domains configured. Running with manual certificates or plain HTTP only.")
	}

	// Initialize and boot reverse proxy listeners
	srv := proxy.NewServer(cfg, acmeMgr)
	if err := srv.Start(ctx); err != nil {
		logger.Fatal("Failed to start server listeners", zap.Error(err))
		return err
	}

	logger.Info("edged Golang Reverse Proxy started successfully. Press Ctrl+C to stop.")

	// Wait for OS shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	sig := <-sigChan
	logger.Info("Received OS shutdown signal, initiating graceful shutdown...", zap.String("signal", sig.String()))

	// Cancel context to stop background tasks (like ACME renewal)
	cancel()

	// Allow up to 30 seconds for active connections to drain
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := srv.Stop(shutdownCtx); err != nil {
		logger.Error("Error during graceful shutdown", zap.Error(err))
		return err
	}
	logger.Info("Graceful shutdown completed cleanly.")
	return nil
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", "config.yaml", "Path to YAML configuration file")
	rootCmd.PersistentFlags().BoolVarP(&testConfig, "test", "t", false, "Validate configuration file and exit")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose logging")
}
