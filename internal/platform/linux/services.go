package linux

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"text/template"

	"github.com/QNester/ai-dev-security-setup/internal/config"
	"github.com/QNester/ai-dev-security-setup/internal/core/services"
	"github.com/QNester/ai-dev-security-setup/internal/fsx"
	"github.com/QNester/ai-dev-security-setup/internal/templates"
)

type Services struct{ Deps Deps }

type serviceData struct {
	NFTFile string
	NFTPath string
}

func (s Services) Install(ctx context.Context, cfg config.Config) error {
	nftPath, err := s.Deps.lookPath("nft")
	if err != nil {
		return err
	}
	values := serviceData{NFTFile: services.NftFile, NFTPath: nftPath}
	unit, err := renderTemplate("linux/ai-dev-isolation.service", values)
	if err != nil {
		return err
	}
	dropIn, err := renderTemplate("linux/nftables-dropin.conf", values)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(services.NftablesDropIn), 0o755); err != nil {
		return fmt.Errorf("create nftables drop-in directory: %w", err)
	}
	for _, item := range []struct {
		path    string
		content []byte
	}{
		{services.UnitPath, unit},
		{services.NftablesDropIn, dropIn},
	} {
		if err := backupFile(services.BackupRoot, item.path); err != nil {
			return err
		}
		if err := fsx.AtomicWriteFile(item.path, item.content, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", item.path, err)
		}
	}
	if _, err := s.Deps.run(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	if _, err := s.Deps.run(ctx, "systemctl", "enable", "--now", services.UnitName); err != nil {
		return fmt.Errorf("enable isolation service: %w", err)
	}
	return s.Verify(ctx, cfg)
}

func (s Services) Verify(ctx context.Context, cfg config.Config) error {
	if _, err := s.Deps.run(ctx, "systemctl", "is-active", "--quiet", services.UnitName); err != nil {
		return fmt.Errorf("isolation service is not active: %w", err)
	}
	for _, path := range []string{services.UnitPath, services.NftablesDropIn} {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular file", path)
		}
	}
	return nil
}

func (s Services) Remove(ctx context.Context, cfg config.Config) error {
	_, _ = s.Deps.run(ctx, "systemctl", "disable", "--now", services.UnitName)
	for _, path := range []string{services.UnitPath, services.NftablesDropIn} {
		if err := os.Remove(path); err != nil && !isNotExist(err) {
			return fmt.Errorf("remove %s: %w", path, err)
		}
	}
	_ = os.Remove(filepath.Dir(services.NftablesDropIn))
	_, _ = s.Deps.run(ctx, "systemctl", "daemon-reload")
	return nil
}

func renderTemplate(name string, value any) ([]byte, error) {
	data, err := templates.FS.ReadFile(name)
	if err != nil {
		return nil, err
	}
	tmpl, err := template.New(name).Option("missingkey=error").Parse(string(data))
	if err != nil {
		return nil, err
	}
	var output bytes.Buffer
	if err := tmpl.Execute(&output, value); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}
