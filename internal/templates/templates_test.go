package templates

import "testing"

func TestTemplatesAreEmbedded(t *testing.T) {
	for _, name := range []string{
		"linux/ai-dev-isolation.service",
		"linux/ai-dev-isolation.nft",
		"darwin/ai-sandbox.plist",
		"darwin/ai-sandbox.sb",
	} {
		data, err := FS.ReadFile(name)
		if err != nil || len(data) == 0 {
			t.Fatalf("%s: len=%d err=%v", name, len(data), err)
		}
	}
}
