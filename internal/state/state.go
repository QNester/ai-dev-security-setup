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
	Root string
}

func (s Store) Load() (State, error) {
	return s.load(true)
}

func (s Store) load(checkPath bool) (State, error) {
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
	if checkPath && s.Path != value.Config.StatePath {
		return value, errors.New("state store path does not match config state_path")
	}
	return value, nil
}

func (s Store) Save(value State) error {
	if s.Path != value.Config.StatePath {
		return errors.New("state store path does not match config state_path")
	}
	if err := value.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return fsx.AtomicWriteFileInRoot(s.root(), s.Path, data, 0o600)
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
	if err := fsx.AtomicWriteFileInRoot(s.root(), backup.Path, data, 0o600); err != nil {
		return Backup{}, err
	}
	return backup, nil
}

func (s Store) Restore(path string) error {
	backupStore := Store{Path: path}
	value, err := backupStore.load(false)
	if err != nil {
		return fmt.Errorf("load backup: %w", err)
	}
	return s.Save(value)
}

func (s Store) root() string {
	if s.Root != "" {
		return s.Root
	}
	return "/"
}
