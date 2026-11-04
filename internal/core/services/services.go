// Package services contains portable service and launcher lifecycle policy.
package services

import (
	"path/filepath"

	"github.com/QNester/ai-dev-security-setup/internal/config"
)

const (
	BackupRoot      = "/var/backups/ai-sandbox"
	NftFile         = "/etc/nftables/ai-dev-isolation.nft"
	AppArmorProfile = "/etc/apparmor.d/ai-dev-bwrap-userns"
	SystemdDir      = "/etc/systemd/system"
	NftablesDropIn  = "/etc/systemd/system/nftables.service.d/ai-dev-isolation.conf"
	UnitName        = "ai-dev-isolation.service"
	UnitPath        = "/etc/systemd/system/ai-dev-isolation.service"
	LibexecDir      = "/usr/local/libexec"
	LibexecPath     = "/usr/local/libexec/sandboxctl"
	LauncherDir     = "/usr/local/bin"
	ReviewLauncher  = "/usr/local/bin/ai-review-file"
	FirewallTable   = "ai_dev_isolation"
	FirewallType    = "nftables"
	OpenCodeHost    = "127.0.0.2"
	OpenCodePort    = 49374
)

// Record describes one generated path owned by the installation.
type Record struct {
	Name string
	Path string
}

// LauncherName is the argv0 symlink for a toolkit CLI.
func LauncherName(tool string) string { return tool + "-secure" }

// LauncherPath returns the installed launcher path for a CLI.
func LauncherPath(tool string) string { return filepath.Join(LauncherDir, LauncherName(tool)) }

// Launchers returns the selected launcher records.
func Launchers(cfg config.Config) []Record {
	result := make([]Record, 0, len(cfg.CLIs))
	for _, cli := range cfg.CLIs {
		result = append(result, Record{Name: LauncherName(cli), Path: LauncherPath(cli)})
	}
	return result
}

// AllLaunchers lists every launcher that uninstall may need to remove.
func AllLaunchers() []string {
	clis := config.SupportedCLIs
	result := make([]string, 0, len(clis))
	for _, cli := range clis {
		result = append(result, LauncherPath(cli))
	}
	return append(result, ReviewLauncher)
}

// ServiceRecords returns the systemd/service records persisted in state.
func ServiceRecords() []Record {
	return []Record{
		{Name: "ai-dev-isolation", Path: UnitPath},
		{Name: "nftables-ai-dev-isolation", Path: NftablesDropIn},
		{Name: "apparmor-ai-dev-bwrap", Path: AppArmorProfile},
	}
}
