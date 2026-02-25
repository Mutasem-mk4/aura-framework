package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "aura",
	Short: "Aura is a smart offensive decision support system",
	Long: `Aura (by Zalami) is an advanced reconnaissance orchestrator 
that connects findings from multiple security tools and uses AI 
to identify the most critical attack paths.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Welcome to Aura — The Offensive Recon Engine")
		fmt.Println("Use 'aura --help' for available commands.")
	},
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
