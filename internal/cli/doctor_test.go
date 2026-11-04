package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/QNester/ai-dev-security-setup/internal/platform/detect"
)

func controlledDetector(healthy bool) *detect.Detector {
	return &detect.Detector{
		GOARCH: "amd64", EUID: 0,
		LookPath: func(name string) (string, error) {
			if healthy {
				return "/usr/bin/" + name, nil
			}
			return "", errors.New("missing")
		},
		ReadFile: func(string) ([]byte, error) { return []byte("1\n"), nil },
		Stat: func(string) (os.FileInfo, error) {
			if healthy {
				return nil, nil
			}
			return nil, errors.New("missing")
		},
	}
}

func TestDoctorExitCodes(t *testing.T) {
	for _, test := range []struct {
		name    string
		healthy bool
		code    int
	}{
		{name: "healthy", healthy: true, code: ExitOK},
		{name: "missing capabilities", healthy: false, code: ExitFailure},
	} {
		t.Run(test.name, func(t *testing.T) {
			app, _, _ := testApp()
			app.Detector = controlledDetector(test.healthy)
			if code := app.Run(context.Background(), "sandboxctl", []string{"doctor"}); code != test.code {
				t.Fatalf("code=%d want=%d", code, test.code)
			}
		})
	}
}

func TestDoctorFixRequiresYes(t *testing.T) {
	app, _, stderr := testApp()
	if code := app.Run(context.Background(), "sandboxctl", []string{"doctor", "--fix"}); code != ExitUsage {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(stderr.String(), "--yes") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestDoctorFixRejectsJSON(t *testing.T) {
	app, _, _ := testApp()
	if code := app.Run(context.Background(), "sandboxctl", []string{"doctor", "--fix", "--yes", "--json"}); code != ExitUsage {
		t.Fatalf("code=%d", code)
	}
}

func TestJSONTrueEnablesStructuredErrors(t *testing.T) {
	app, _, stderr := testApp()
	code := app.Run(context.Background(), "sandboxctl", []string{"doctor", "--backend", "vm", "--json=true"})
	if code != ExitUsage {
		t.Fatalf("code=%d", code)
	}
	var payload map[string]any
	if err := json.Unmarshal(stderr.Bytes(), &payload); err != nil {
		t.Fatalf("stderr=%q err=%v", stderr.String(), err)
	}
}
