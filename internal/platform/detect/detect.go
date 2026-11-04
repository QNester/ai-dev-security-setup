// Package detect reports host capabilities without modifying the host.
package detect

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	Pass = "pass"
	Warn = "warn"
	Fail = "fail"
)

type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type Report struct {
	OS       string   `json:"os"`
	Arch     string   `json:"arch"`
	Backend  string   `json:"backend"`
	Checks   []Check  `json:"checks"`
	Warnings []string `json:"warnings"`
}

func (r Report) Healthy() bool {
	for _, check := range r.Checks {
		if check.Status == Fail {
			return false
		}
	}
	return true
}

type Detector struct {
	GOOS     string
	GOARCH   string
	EUID     int
	LookPath func(string) (string, error)
	ReadFile func(string) ([]byte, error)
	Stat     func(string) (os.FileInfo, error)
}

func NewDetector() Detector {
	return Detector{
		GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, EUID: os.Geteuid(),
		LookPath: exec.LookPath, ReadFile: os.ReadFile, Stat: os.Stat,
	}
}

func ResolveBackend(platform, requested string) (string, error) {
	switch platform {
	case "linux":
		switch requested {
		case "", "auto", "native":
			return "bwrap", nil
		default:
			return "", fmt.Errorf("backend %q is not supported on Linux", requested)
		}
	case "darwin":
		switch requested {
		case "", "auto", "vm":
			return "vm", nil
		case "native":
			return "seatbelt", nil
		default:
			return "", fmt.Errorf("backend %q is not supported on macOS", requested)
		}
	default:
		return "", fmt.Errorf("unsupported platform %q", platform)
	}
}

func (d Detector) Inspect(backend string) (Report, error) {
	if d.GOOS == "" {
		d.GOOS = runtime.GOOS
	}
	if d.GOARCH == "" {
		d.GOARCH = runtime.GOARCH
	}
	if d.LookPath == nil {
		d.LookPath = exec.LookPath
	}
	if d.ReadFile == nil {
		d.ReadFile = os.ReadFile
	}
	if d.Stat == nil {
		d.Stat = os.Stat
	}
	resolved, err := ResolveBackend(d.GOOS, backend)
	if err != nil {
		return Report{}, err
	}
	report := Report{OS: d.GOOS, Arch: d.GOARCH, Backend: resolved}
	if d.GOARCH != "amd64" && d.GOARCH != "arm64" {
		report.add(Fail, "architecture", "only amd64 and arm64 are supported")
	} else {
		report.add(Pass, "architecture", d.GOARCH)
	}
	if d.EUID == 0 {
		report.add(Pass, "privileges", "running as root")
	} else if d.hasCommand("sudo") {
		report.add(Pass, "privileges", "not root; sudo is available")
	} else {
		report.add(Fail, "privileges", "root or sudo is required")
	}
	switch d.GOOS {
	case "linux":
		d.inspectLinux(&report)
	case "darwin":
		d.inspectDarwin(&report)
		d.inspectVM(&report)
	default:
		report.add(Fail, "operating system", "only Linux and macOS are supported")
	}
	return report, nil
}

func (d Detector) inspectLinux(report *Report) {
	report.add(Pass, "operating system", "Linux")
	d.commandCheck(report, "systemctl", true, "systemd")
	if _, err := d.Stat("/run/systemd/system"); err != nil {
		report.add(Fail, "systemd runtime", "/run/systemd/system is unavailable")
	} else {
		report.add(Pass, "systemd runtime", "running systemd instance detected")
	}
	d.commandCheck(report, "bwrap", true, "bubblewrap")
	d.inspectUserNamespaces(report)
	d.commandCheck(report, "nft", true, "nftables")
	d.commandCheck(report, "setfacl", true, "POSIX ACL")
	d.commandCheck(report, "apt-get", true, "package manager")
	report.Warnings = append(report.Warnings,
		"UID-based nftables filtering is best-effort, not VM-grade network isolation")
}

func (d Detector) inspectDarwin(report *Report) {
	report.add(Pass, "operating system", "macOS")
	d.commandCheck(report, "launchctl", true, "launchd")
	for _, command := range []string{"dscl", "sysadminctl", "dseditgroup"} {
		d.commandCheck(report, command, report.Backend == "seatbelt", "macOS account management")
	}
	if d.hasCommand("chmod") {
		report.add(Pass, "chmod ACL", "macOS extended ACL support is available")
	} else {
		report.add(Fail, "chmod ACL", "chmod is required")
	}
	if d.hasCommand("sandbox-exec") {
		report.add(Warn, "sandbox-exec", "present but deprecated; native isolation is best-effort")
	} else if report.Backend == "seatbelt" {
		report.add(Fail, "sandbox-exec", "required by the native backend")
	} else {
		report.add(Warn, "sandbox-exec", "not found; native backend is unavailable")
	}
	report.Warnings = append(report.Warnings,
		"native Seatbelt does not provide parity with Linux; auto selects the VM backend")
}

func (d Detector) inspectVM(report *Report) {
	lima := d.hasCommand("limactl")
	utm := d.hasCommand("utmctl")
	if _, err := d.Stat("/Applications/UTM.app"); err == nil {
		utm = true
	}
	if lima {
		report.add(Pass, "lima", "limactl found")
	} else {
		report.add(Warn, "lima", "not found")
	}
	if utm {
		report.add(Pass, "UTM", "UTM found")
	} else {
		report.add(Warn, "UTM", "not found")
	}
	if report.Backend == "vm" && !lima && !utm {
		report.add(Fail, "VM backend", "install Lima or UTM, or use --backend native for best-effort macOS isolation")
	}
}

func (d Detector) inspectUserNamespaces(report *Report) {
	if data, err := d.ReadFile("/proc/sys/kernel/unprivileged_userns_clone"); err == nil && strings.TrimSpace(string(data)) == "0" {
		report.add(Fail, "user namespaces", "unprivileged user namespaces are disabled")
		return
	}
	if data, err := d.ReadFile("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"); err == nil && strings.TrimSpace(string(data)) == "1" {
		report.add(Warn, "user namespaces", "AppArmor restriction is enabled; a targeted Bubblewrap profile is required")
		return
	}
	report.add(Pass, "user namespaces", "no disabling sysctl detected")
}

func (d Detector) commandCheck(report *Report, command string, required bool, label string) {
	if d.hasCommand(command) {
		report.add(Pass, label, command+" found")
		return
	}
	status := Warn
	if required {
		status = Fail
	}
	report.add(status, label, command+" not found")
}

func (d Detector) hasCommand(name string) bool {
	if _, err := d.LookPath(name); err == nil {
		return true
	}
	// Homebrew installs into a prefix that may not be on the PATH of the
	// process that just performed the installation.
	for _, directory := range []string{"/opt/homebrew/bin", "/usr/local/bin"} {
		if info, err := d.Stat(filepath.Join(directory, name)); err == nil && info != nil &&
			!info.IsDir() && info.Mode().Perm()&0o111 != 0 {
			return true
		}
	}
	return false
}

func (r *Report) add(status, name, detail string) {
	r.Checks = append(r.Checks, Check{Name: name, Status: status, Detail: detail})
}

func IsNotFound(err error) bool {
	return errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist)
}
