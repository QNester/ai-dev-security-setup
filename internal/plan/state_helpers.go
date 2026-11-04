package plan

import "github.com/QNester/ai-dev-security-setup/internal/state"

func firewallType(st state.State) string {
	if st.Firewall == nil {
		return "no"
	}
	return st.Firewall.Type
}
