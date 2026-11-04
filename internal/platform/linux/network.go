package linux

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/template"

	"github.com/QNester/ai-dev-security-setup/internal/config"
	"github.com/QNester/ai-dev-security-setup/internal/core/services"
	"github.com/QNester/ai-dev-security-setup/internal/fsx"
	"github.com/QNester/ai-dev-security-setup/internal/platform/base"
	"github.com/QNester/ai-dev-security-setup/internal/templates"
)

const nftTemplatePath = "linux/ai-dev-isolation.nft"

type Network struct{ Deps Deps }

type nftData struct {
	AIUID          uint32
	IPv4Exceptions string
	IPv6Exceptions string
}

func (n Network) Apply(ctx context.Context, cfg config.Config) error {
	ids, err := n.Deps.LookupIDs(cfg)
	if err != nil {
		return err
	}
	resolv, err := n.Deps.readFile("/etc/resolv.conf")
	if err != nil {
		return fmt.Errorf("read /etc/resolv.conf: %w", err)
	}
	servers := nameservers(resolv)
	if len(servers) == 0 {
		return errors.New("no valid nameservers found in /etc/resolv.conf")
	}
	endpoints := make([]base.Endpoint, 0, 2)
	if contains(cfg.CLIs, "opencode") {
		endpoints = append(endpoints, base.Endpoint{
			Host: services.OpenCodeHost, Port: services.OpenCodePort, Protocol: "tcp",
		})
	}
	if endpoint, ok := litellmEndpoint(cfg.LiteLLMBaseURL); ok {
		endpoints = append(endpoints, endpoint)
	}
	content, err := renderNFT(ids.User, servers, endpoints)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(services.NftFile), 0o755); err != nil {
		return err
	}
	if err := backupFile(services.BackupRoot, services.NftFile); err != nil {
		return err
	}
	if err := fsx.AtomicWriteFile(services.NftFile, content, 0o644); err != nil {
		return fmt.Errorf("write nftables rules: %w", err)
	}
	if _, err := n.Deps.run(ctx, "nft", "-c", "-f", services.NftFile); err != nil {
		return fmt.Errorf("validate nftables rules: %w", err)
	}
	if _, err := n.Deps.run(ctx, "nft", "-f", services.NftFile); err != nil {
		return fmt.Errorf("apply nftables rules: %w", err)
	}
	return n.Verify(ctx, cfg)
}

func renderNFT(uid uint32, servers []string, endpoints []base.Endpoint) ([]byte, error) {
	data, err := templates.FS.ReadFile(nftTemplatePath)
	if err != nil {
		return nil, err
	}
	v4 := map[string]bool{}
	v6 := map[string]bool{}
	for _, server := range servers {
		address, err := netip.ParseAddr(server)
		if err != nil {
			continue
		}
		address = address.Unmap()
		for _, protocol := range []string{"udp", "tcp"} {
			if address.Is4() {
				v4[dnsRule(uid, "ip", address, protocol)] = true
			} else {
				v6[dnsRule(uid, "ip6", address, protocol)] = true
			}
		}
	}
	for _, endpoint := range endpoints {
		for _, address := range endpointAddresses(endpoint.Host) {
			if address.Is4() {
				v4[endpointRule(uid, "ip", address, endpoint.Protocol, endpoint.Port)] = true
			} else {
				v6[endpointRule(uid, "ip6", address, endpoint.Protocol, endpoint.Port)] = true
			}
		}
	}
	value := nftData{
		AIUID:          uid,
		IPv4Exceptions: joinRules(v4),
		IPv6Exceptions: joinRules(v6),
	}
	tmpl, err := template.New(nftTemplatePath).Option("missingkey=error").Parse(string(data))
	if err != nil {
		return nil, err
	}
	var output bytes.Buffer
	if err := tmpl.Execute(&output, value); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func nameservers(data []byte) []string {
	seen := map[string]bool{}
	var result []string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		value := strings.SplitN(fields[1], "%", 2)[0]
		if _, err := netip.ParseAddr(value); err != nil || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func litellmEndpoint(raw string) (base.Endpoint, bool) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" {
		return base.Endpoint{}, false
	}
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	value, err := strconv.ParseUint(port, 10, 16)
	if err != nil || value == 0 {
		return base.Endpoint{}, false
	}
	host := parsed.Hostname()
	if host == "localhost" {
		host = "127.0.0.1"
	}
	return base.Endpoint{Host: host, Port: uint16(value), Protocol: "tcp"}, true
}

func endpointAddresses(host string) []netip.Addr {
	if address, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{address.Unmap()}
	}
	lookup, err := net.LookupIP(host)
	if err != nil {
		return nil
	}
	seen := map[netip.Addr]bool{}
	result := make([]netip.Addr, 0, len(lookup))
	for _, value := range lookup {
		address, ok := netip.AddrFromSlice(value)
		if !ok {
			continue
		}
		address = address.Unmap()
		if !seen[address] {
			seen[address] = true
			result = append(result, address)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Less(result[j]) })
	return result
}

func dnsRule(uid uint32, family string, address netip.Addr, protocol string) string {
	return fmt.Sprintf("        meta skuid %d %s daddr %s %s dport 53 counter accept",
		uid, family, address, protocol)
}

func endpointRule(uid uint32, family string, address netip.Addr, protocol string, port uint16) string {
	return fmt.Sprintf("        meta skuid %d %s daddr %s %s dport %d counter accept",
		uid, family, address, protocol, port)
}

func joinRules(values map[string]bool) string {
	if len(values) == 0 {
		return ""
	}
	keys := make([]string, 0, len(values))
	for value := range values {
		keys = append(keys, value)
	}
	sort.Strings(keys)
	return strings.Join(keys, "\n")
}

func (n Network) Verify(ctx context.Context, cfg config.Config) error {
	for _, family := range []string{"ip", "ip6"} {
		if _, err := n.Deps.run(ctx, "nft", "list", "table", family, services.FirewallTable); err != nil {
			return fmt.Errorf("nftables table %s %s is missing: %w", family, services.FirewallTable, err)
		}
	}
	return nil
}

func (n Network) Remove(ctx context.Context, cfg config.Config) error {
	for _, family := range []string{"ip", "ip6", "inet"} {
		_, _ = n.Deps.run(ctx, "nft", "delete", "table", family, services.FirewallTable)
	}
	if err := os.Remove(services.NftFile); err != nil && !isNotExist(err) {
		return fmt.Errorf("remove nftables rules: %w", err)
	}
	return nil
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
