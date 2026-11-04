package base

import "testing"

func validSpec() Spec {
	return Spec{
		Argv: []string{"/usr/bin/true"}, Cwd: "/home/ai-dev", Network: NetworkOpen,
		DNSServers:       []string{"192.168.1.1"},
		AllowedEndpoints: []Endpoint{{Host: "127.0.0.1", Port: 4000, Protocol: "tcp"}},
		ReviewFD:         -1,
	}
}

func TestSpecValidation(t *testing.T) {
	if err := validSpec().Validate(); err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*Spec){
		"relative cwd":       func(s *Spec) { s.Cwd = "relative" },
		"readonly traversal": func(s *Spec) { s.ReadOnlyPaths = []string{"/usr/../etc"} },
		"writable traversal": func(s *Spec) { s.WritablePaths = []string{"relative"} },
		"invalid DNS":        func(s *Spec) { s.DNSServers = []string{"dns.local"} },
		"invalid endpoint": func(s *Spec) {
			s.AllowedEndpoints = []Endpoint{{Host: "bad host", Port: 4000, Protocol: "tcp"}}
		},
		"deny with exception": func(s *Spec) { s.Network = NetworkDeny },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			spec := validSpec()
			mutate(&spec)
			if err := spec.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestSpecRequiresAbsoluteExecutable(t *testing.T) {
	spec := validSpec()
	spec.Argv[0] = "true"
	if err := spec.Validate(); err == nil {
		t.Fatal("relative executable was accepted")
	}
}
