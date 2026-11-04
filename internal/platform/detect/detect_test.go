package detect

import (
	"errors"
	"os"
	"testing"
)

func fakeDetector(platform string) Detector {
	return Detector{
		GOOS: platform, GOARCH: "arm64", EUID: 0,
		LookPath: func(string) (string, error) { return "/usr/bin/tool", nil },
		ReadFile: func(path string) ([]byte, error) {
			if path == "/proc/sys/kernel/unprivileged_userns_clone" {
				return []byte("1\n"), nil
			}
			return []byte("0\n"), nil
		},
		Stat: func(string) (os.FileInfo, error) { return nil, nil },
	}
}

func TestLinuxHealthy(t *testing.T) {
	report, err := fakeDetector("linux").Inspect("auto")
	if err != nil {
		t.Fatal(err)
	}
	if !report.Healthy() || report.Backend != "bwrap" {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestMissingRequiredCapabilityFails(t *testing.T) {
	detector := fakeDetector("linux")
	detector.LookPath = func(name string) (string, error) {
		if name == "bwrap" {
			return "", errors.New("missing")
		}
		return "/usr/bin/" + name, nil
	}
	report, err := detector.Inspect("native")
	if err != nil {
		t.Fatal(err)
	}
	if report.Healthy() {
		t.Fatal("missing Bubblewrap must fail doctor")
	}
}

func TestDarwinAutoSelectsVM(t *testing.T) {
	report, err := fakeDetector("darwin").Inspect("auto")
	if err != nil {
		t.Fatal(err)
	}
	if report.Backend != "vm" || len(report.Warnings) == 0 {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestDarwinVMRequiresProvider(t *testing.T) {
	detector := fakeDetector("darwin")
	detector.LookPath = func(name string) (string, error) {
		switch name {
		case "limactl", "utmctl":
			return "", errors.New("missing")
		default:
			return "/usr/bin/" + name, nil
		}
	}
	detector.Stat = func(string) (os.FileInfo, error) { return nil, errors.New("missing") }
	report, err := detector.Inspect("auto")
	if err != nil {
		t.Fatal(err)
	}
	if report.Healthy() {
		t.Fatal("VM backend without Lima or UTM must fail")
	}
}

func TestRejectInvalidBackend(t *testing.T) {
	if _, err := ResolveBackend("linux", "vm"); err == nil {
		t.Fatal("expected backend error")
	}
}
