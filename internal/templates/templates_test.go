package templates

import (
	"bytes"
	"testing"
	"text/template"
)

var templateFiles = []string{
	"linux/ai-dev-isolation.service",
	"linux/ai-dev-isolation.nft",
	"linux/ai-dev-bwrap.apparmor",
	"darwin/ai-sandbox.plist",
	"darwin/ai-sandbox.sb",
}

func TestTemplatesAreEmbedded(t *testing.T) {
	for _, name := range templateFiles {
		data, err := FS.ReadFile(name)
		if err != nil || len(data) == 0 {
			t.Fatalf("%s: len=%d err=%v", name, len(data), err)
		}
	}
}

func TestTemplatesRender(t *testing.T) {
	values := map[string]any{
		"NFTFile": "/etc/nftables/ai-dev-isolation.nft", "AIUID": 999,
		"IPv4Exceptions": "", "IPv6Exceptions": "", "Tool": "claude",
		"Program": "/opt/ai-tools/bin/claude", "AIHome": "/home/ai-dev",
		"TmpRoot": "/var/lib/ai-sandbox/tmp", "SharedDir": "/home/alice/Developer",
		"NetworkRules": "",
	}
	for _, name := range templateFiles {
		t.Run(name, func(t *testing.T) {
			data, err := FS.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			tmpl, err := template.New(name).Option("missingkey=error").Parse(string(data))
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			if err := tmpl.Execute(&output, values); err != nil {
				t.Fatal(err)
			}
			if output.Len() == 0 {
				t.Fatal("empty rendered template")
			}
		})
	}
}
