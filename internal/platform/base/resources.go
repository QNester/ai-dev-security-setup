package base

// The resource records below are the stable, platform-neutral descriptions of
// everything sandboxctl may create. State persists these records so uninstall
// follows what was installed rather than the current flags.

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

type Launcher struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Target string `json:"target"`
}

type Mount struct {
	Source  string   `json:"source"`
	Target  string   `json:"target"`
	Options []string `json:"options"`
}
