package linux

import (
	"strings"
	"testing"

	"github.com/QNester/ai-dev-security-setup/internal/platform/base"
)

func TestNameserversDeduplicatesAndValidates(t *testing.T) {
	data := []byte("nameserver 1.1.1.1\nnameserver 1.1.1.1\nnameserver 2001:db8::1\nnameserver not-an-ip\n")
	got := nameservers(data)
	if len(got) != 2 || got[0] != "1.1.1.1" || got[1] != "2001:db8::1" {
		t.Fatalf("nameservers=%v", got)
	}
}

func TestRenderNFTSeparatesFamiliesAndSortsRules(t *testing.T) {
	content, err := renderNFT(1001,
		[]string{"1.1.1.1", "2001:db8::1"},
		[]base.Endpoint{{Host: "127.0.0.1", Port: 4000, Protocol: "tcp"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	for _, fragment := range []string{
		"destroy table ip ai_dev_isolation",
		"meta skuid 1001 ip daddr 1.1.1.1 udp dport 53",
		"meta skuid 1001 ip daddr 1.1.1.1 tcp dport 53",
		"meta skuid 1001 ip6 daddr 2001:db8::1 udp dport 53",
		"meta skuid 1001 ip daddr 127.0.0.1 tcp dport 4000",
	} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("missing %q\n%s", fragment, text)
		}
	}
}

func TestLiteLLMEndpointUsesDefaultPortAndLocalhost(t *testing.T) {
	endpoint, ok := litellmEndpoint("http://localhost/v1")
	if !ok || endpoint.Host != "127.0.0.1" || endpoint.Port != 80 || endpoint.Protocol != "tcp" {
		t.Fatalf("endpoint=%+v ok=%v", endpoint, ok)
	}
	endpoint, ok = litellmEndpoint("https://example.com/v1")
	if !ok || endpoint.Port != 443 {
		t.Fatalf("endpoint=%+v ok=%v", endpoint, ok)
	}
}

func TestFindNodeArchivePinsNameAndChecksum(t *testing.T) {
	hash := strings.Repeat("a", 64)
	name, expected, err := findNodeArchive(hash+"  node-v22.1.0-linux-x64.tar.xz\n", "-linux-x64.tar.xz")
	if err != nil {
		t.Fatal(err)
	}
	if name != "node-v22.1.0-linux-x64.tar.xz" || expected != hash {
		t.Fatalf("name=%q expected=%q", name, expected)
	}
	if _, _, err := findNodeArchive("bad  ../../etc/passwd\n", "-linux-x64.tar.xz"); err == nil {
		t.Fatal("invalid archive name was accepted")
	}
}

func TestValidateSymlinkRejectsWritableEscape(t *testing.T) {
	source := "/opt/ai-tools/runtime"
	if err := validateSymlinkTarget(source, source+"/bin/tool", "/usr/bin/true", []string{"/home/ai-dev", "/tmp"}); err != nil {
		t.Fatalf("read-only target was rejected: %v", err)
	}
	if err := validateSymlinkTarget(source, source+"/bin/tool", "/tmp/evil", []string{"/tmp"}); err == nil {
		t.Fatal("writable symlink target was accepted")
	}
	if err := validateSymlinkTarget(source, source+"/bin/tool", "../../../../etc/passwd", []string{"/tmp"}); err != nil {
		t.Fatalf("relative read-only target was rejected: %v", err)
	}
}
