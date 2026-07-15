package tui

import (
	"fmt"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"

	pkgapi "github.com/reloadlife/netpolicyd/pkg/api"
)

// Config for the TUI.
type Config struct {
	Client          *pkgapi.Client
	Endpoint        string
	RefreshInterval time.Duration
	// EasyMode starts in plain-language UI (default true). false = advanced.
	EasyMode *bool
}

// Run starts the full-screen Bubble Tea program.
func Run(cfg Config) error {
	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = 2 * time.Second
	}
	// Bubble Tea needs a real interactive terminal.
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		return fmt.Errorf("tui requires an interactive terminal (stdin/stdout must be a tty)\nrun: netpolicyctl   # in a real shell, not a pipe/script")
	}
	m := newRootModel(cfg)
	// Alt screen only — mouse capture breaks many terminals / SSH clients.
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}
