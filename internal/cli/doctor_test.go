package cli

import (
	"context"
	"errors"
	"os"
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
