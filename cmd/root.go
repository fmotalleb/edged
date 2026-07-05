/*
Copyright © 2026 Motalleb Fallahnehzad

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package cmd

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/fmotalleb/edged/internal/acme"
	"github.com/fmotalleb/edged/internal/config"
	"github.com/fmotalleb/edged/internal/proxy"
)

var (
	configPath string
	dryRun     bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "edged",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	RunE: func(cmd *cobra.Command, args []string) error {
		if configPath == "" {
			return errors.New("config path must be given")
		}
		log.SetFlags(log.LstdFlags | log.Lshortfile)
		log.Printf("[Main] Loading configuration from: %s", configPath)

		cfg, err := config.Load(configPath)
		if err != nil {
			log.Fatalf("[Main] Fatal configuration error: %v", err)
		}

		if dryRun {
			fmt.Printf("Configuration file '%s' is valid!\n", configPath)
			os.Exit(0)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Initialize ACME Let's Encrypt Manager if ACME TLS is configured
		var acmeMgr *acme.Manager
		acmeDomains := cfg.GetAllACMEDomains()
		if len(acmeDomains) > 0 {
			log.Printf("[Main] Initializing ACME Let's Encrypt Manager for domains: %v", acmeDomains)
			acmeMgr, err = acme.NewManager(cfg.ACME)
			if err != nil {
				log.Fatalf("[Main] Failed to initialize ACME Manager: %v", err)
			}

			// Ensure all required certificates are present or obtain them via DNS-01 / HTTP-01
			log.Printf("[Main] Verifying TLS certificates for configured domains...")
			if err := acmeMgr.EnsureDomains(acmeDomains); err != nil {
				log.Printf("[Main] Warning during certificate verification/acquisition: %v", err)
				log.Printf("[Main] Note: The server will continue booting and attempt on-demand acquisition during TLS handshakes.")
			}

			// Start background certificate renewal loop
			acmeMgr.StartRenewalDaemon(ctx, acmeDomains)
		} else {
			log.Println("[Main] No ACME TLS domains configured. Running with manual certificates or plain HTTP only.")
		}

		// Initialize and boot reverse proxy listeners
		srv := proxy.NewServer(cfg, acmeMgr)
		if err := srv.Start(); err != nil {
			log.Fatalf("[Main] Failed to start server listeners: %v", err)
		}

		log.Println("[Main] Golang Reverse Proxy started successfully. Press Ctrl+C to stop.")

		// Wait for OS shutdown signals
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		sig := <-sigChan
		log.Printf("[Main] Received OS signal (%s). Starting graceful shutdown...", sig)

		// Cancel context to stop background tasks (like ACME renewal)
		cancel()

		// Allow up to 30 seconds for active connections to drain
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()

		if err := srv.Stop(shutdownCtx); err != nil {
			log.Printf("[Main] Error during graceful shutdown: %v", err)
		} else {
			log.Println("[Main] Graceful shutdown completed cleanly.")
		}
		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringVarP(&configPath, "config", "c", "", "Config file path")
	rootCmd.Flags().BoolVarP(&dryRun, "dry-run", "t", false, "Validate config file")
}
