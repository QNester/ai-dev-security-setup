// Package state persists the system integration owned by sandboxctl.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/QNester/ai-dev-security-setup/internal/config"
	"github.com/QNester/ai-dev-security-setup/internal/fsx"
)

const Version = 1

type State struct {
	Version  int           `json:"version"`
	Platform string        `json:"platform"`
	Backend  string        `json:"backend"`
	Config   config.Config `json:"config"`
	Created  Created       `json:"created"`
	Shared   Shared        `json:"shared"`
	Services []Service     `json:"services"`
	Firewall *Firewall     `json:"firewall,omitempty"`
	Runtime  Runtime       `json:"runtime"`
	Backups  []Backup      `json:"backups"`
}

type Created struct {
	User  string `json:"user"`
	Group string `json:"group"`
}

type Shared struct {
	Path  string `json:"path"`
	ACL   string `json:"acl"`
	Alias string `json:"alias"`
}

type Service struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

type Firewall struct {
	Type  string `json:"type"`
	Table string `json:"table"`
}

type Runtime struct {
	Path string   `json:"path"`
	CLIs []string `json:"clis"`
}

type Backup struct {
	Source string `json:"source"`
	Path   string `json:"path"`
}

type Store struct {
	Path string
}

func (s Store) Load() (State, error) {
	var value State
	file, err := fsx.SafeOpenRegular(s.Path)
	if err != nil {
		return value, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, fmt.Errorf("decode state: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return value, errors.New("state contains multiple JSON values")
		}
		return value, err
	}
	if err := value.Validate(); err != nil {
		return value, err
	}
	return value, nil
}

func (s Store) Save(value State) error {
	if err := value.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return fsx.AtomicWriteFile(s.Path, data, 0o600)
}

func (s Store) Backup() (Backup, error) {
	file, err := fsx.SafeOpenRegular(s.Path)
	if err != nil {
		return Backup{}, err
	}
	data, readErr := io.ReadAll(file)
	closeErr := file.Close()
	if readErr != nil {
		return Backup{}, readErr
	}
	if closeErr != nil {
		return Backup{}, closeErr
	}
	backup := Backup{
		Source: s.Path,
		Path:   fmt.Sprintf("%s.%d.bak", s.Path, time.Now().UnixNano()),
	}
	if err := fsx.AtomicWriteFile(backup.Path, data, 0o600); err != nil {
		return Backup{}, err
	}
	return backup, nil
}

func (s Store) Restore(path string) error {
	backupStore := Store{Path: path}
	value, err := backupStore.Load()
	if err != nil {
		return fmt.Errorf("load backup: %w", err)
	}
	return s.Save(value)
}

func (s State) Validate() error {
	if s.Version != Version {
		return fmt.Errorf("unsupported state version %d", s.Version)
	}
	if s.Platform != "linux" && s.Platform != "darwin" {
		return fmt.Errorf("unsupported state platform %q", s.Platform)
	}
	if s.Backend == "" {
		return errors.New("state backend is required")
	}
	return s.Config.Validate()
}
