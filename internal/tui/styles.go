package tui

import "github.com/charmbracelet/lipgloss"

// Adaptive colors: readable on both dark and light terminals.
// Accent is amber/orange for the netpolicyd TUI.
var (
	cAccent  = lipgloss.AdaptiveColor{Light: "#C2410C", Dark: "#FDBA74"} // amber
	cAccent2 = lipgloss.AdaptiveColor{Light: "#0E7490", Dark: "#67E8F9"}
	cText    = lipgloss.AdaptiveColor{Light: "#111827", Dark: "#F3F4F6"}
	cMuted   = lipgloss.AdaptiveColor{Light: "#6B7280", Dark: "#9CA3AF"}
	cBorder  = lipgloss.AdaptiveColor{Light: "#FDBA74", Dark: "#9A3412"}
	cOK      = lipgloss.AdaptiveColor{Light: "#047857", Dark: "#34D399"}
	cWarn    = lipgloss.AdaptiveColor{Light: "#B45309", Dark: "#FBBF24"}
	cErr     = lipgloss.AdaptiveColor{Light: "#B91C1C", Dark: "#F87171"}
	cSelFg   = lipgloss.AdaptiveColor{Light: "#FFFFFF", Dark: "#1C0A00"}
	cSelBg   = lipgloss.AdaptiveColor{Light: "#C2410C", Dark: "#FDBA74"}
	cBarBg   = lipgloss.AdaptiveColor{Light: "#FFF7ED", Dark: "#431407"}
	cBarFg   = lipgloss.AdaptiveColor{Light: "#9A3412", Dark: "#FFEDD5"}
	cBadgeFg = lipgloss.AdaptiveColor{Light: "#064E3B", Dark: "#022C22"}
	cUpBg    = lipgloss.AdaptiveColor{Light: "#6EE7B7", Dark: "#059669"}
	cDownBg  = lipgloss.AdaptiveColor{Light: "#D1D5DB", Dark: "#4B5563"}
	cHead    = lipgloss.AdaptiveColor{Light: "#9A3412", Dark: "#FDBA74"}
)

var (
	tabActive    = lipgloss.NewStyle().Bold(true).Foreground(cSelFg).Background(cSelBg).Padding(0, 2)
	tabInactive  = lipgloss.NewStyle().Foreground(cMuted).Padding(0, 2)
	helpStyle    = lipgloss.NewStyle().Foreground(cMuted)
	errStyle     = lipgloss.NewStyle().Foreground(cErr).Bold(true)
	okStyle      = lipgloss.NewStyle().Foreground(cOK).Bold(true)
	warnStyle    = lipgloss.NewStyle().Foreground(cWarn).Bold(true)
	headerStyle  = lipgloss.NewStyle().Bold(true).Foreground(cHead)
	statusStyle  = lipgloss.NewStyle().Foreground(cBarFg).Background(cBarBg).Padding(0, 1)
	titleStyle   = lipgloss.NewStyle().Bold(true).Foreground(cAccent).MarginBottom(1)
	panelStyle   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(cBorder).Padding(1, 2)
	labelStyle   = lipgloss.NewStyle().Foreground(cAccent2).Width(18)
	valueStyle   = lipgloss.NewStyle().Foreground(cText)
	focusStyle   = lipgloss.NewStyle().Bold(true).Foreground(cSelFg).Background(cSelBg)
	dimStyle     = lipgloss.NewStyle().Foreground(cMuted)
	selStyle     = lipgloss.NewStyle().Bold(true).Foreground(cSelFg).Background(cSelBg)
	badgeUp      = lipgloss.NewStyle().Foreground(cBadgeFg).Background(cUpBg).Padding(0, 1).Bold(true)
	badgeDown    = lipgloss.NewStyle().Foreground(cText).Background(cDownBg).Padding(0, 1)
	sectionStyle = lipgloss.NewStyle().Bold(true).Foreground(cAccent)
)
