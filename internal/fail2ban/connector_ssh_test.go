// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the GNU Affero General Public License, Version 3 (AGPL-3.0)
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	https://www.gnu.org/licenses/agpl-3.0.en.html
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fail2ban

import (
	"testing"

	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

func TestResolveTunnelPort(t *testing.T) {
	SetProvider(testProvider{})
	defer SetProvider(noopProvider{})

	cases := []struct {
		name string
		srv  shared.Fail2banServer
		want int
	}{
		{"explicit port", shared.Fail2banServer{Name: "s", TunnelPort: 9443}, 9443},
		{"zero falls back to UI port", shared.Fail2banServer{Name: "s"}, 8080},
		{"privileged port falls back to UI port", shared.Fail2banServer{Name: "s", TunnelPort: 80}, 8080},
		{"out of range falls back to UI port", shared.Fail2banServer{Name: "s", TunnelPort: 70000}, 8080},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveTunnelPort(tc.srv); got != tc.want {
				t.Fatalf("resolveTunnelPort(%+v) = %d, want %d", tc.srv.TunnelPort, got, tc.want)
			}
		})
	}
}

func TestResolveTunnelPortNoopProviderFallback(t *testing.T) {
	SetProvider(noopProvider{})
	defer SetProvider(noopProvider{})

	if got := resolveTunnelPort(shared.Fail2banServer{Name: "s"}); got != 8080 {
		t.Fatalf("resolveTunnelPort with noop provider = %d, want 8080", got)
	}
}

func TestActionCallbackURL(t *testing.T) {
	SetProvider(testProvider{})
	defer SetProvider(noopProvider{})

	tunneled := &SSHConnector{server: shared.Fail2banServer{Name: "s"}, tunnelPort: 9443}
	if got := tunneled.actionCallbackURL(); got != "http://localhost:9443" {
		t.Fatalf("tunneled actionCallbackURL = %q, want http://localhost:9443", got)
	}

	direct := &SSHConnector{server: shared.Fail2banServer{Name: "s"}}
	if got := direct.actionCallbackURL(); got != "http://127.0.0.1:8080" {
		t.Fatalf("direct actionCallbackURL = %q, want provider callback URL", got)
	}
}

func TestBuildSSHArgsReverseTunnelForwardTarget(t *testing.T) {
	SetProvider(testProvider{})
	defer SetProvider(noopProvider{})

	findR := func(args []string) string {
		for i, a := range args {
			if a == "-R" && i+1 < len(args) {
				return args[i+1]
			}
		}
		return ""
	}

	custom := &SSHConnector{
		server:      shared.Fail2banServer{Host: "10.0.0.1", SSHUser: "f2b"},
		tunnelPort:  18080,
		forwardPort: 8080,
	}
	if got := findR(custom.buildSSHArgs([]string{"true"})); got != "18080:localhost:8080" {
		t.Fatalf("-R arg = %q, want 18080:localhost:8080", got)
	}

	deflt := &SSHConnector{
		server:      shared.Fail2banServer{Host: "10.0.0.1", SSHUser: "f2b"},
		tunnelPort:  8080,
		forwardPort: 8080,
	}
	if got := findR(deflt.buildSSHArgs([]string{"true"})); got != "8080:localhost:8080" {
		t.Fatalf("-R arg = %q, want 8080:localhost:8080", got)
	}

	noTunnel := &SSHConnector{server: shared.Fail2banServer{Host: "10.0.0.1", SSHUser: "f2b"}}
	if got := findR(noTunnel.buildSSHArgs([]string{"true"})); got != "" {
		t.Fatalf("unexpected -R arg %q for connector without tunnel", got)
	}
}

func TestSSHTunnelConfigChanged(t *testing.T) {
	SetProvider(testProvider{})
	defer SetProvider(noopProvider{})

	base := shared.Fail2banServer{
		Type: "ssh", Host: "10.0.0.1", Port: 22, SSHUser: "f2b", SSHKeyPath: "/config/.ssh/id",
		ReverseTunnelEnabled: true, TunnelPort: 9443,
	}
	tunneled := &SSHConnector{server: base, tunnelPort: 9443}

	cases := []struct {
		name   string
		old    *SSHConnector
		mutate func(shared.Fail2banServer) shared.Fail2banServer
		want   bool
	}{
		{"unchanged", tunneled, func(s shared.Fail2banServer) shared.Fail2banServer { return s }, false},
		{"no old tunnel, tunnel newly enabled", &SSHConnector{server: base}, func(s shared.Fail2banServer) shared.Fail2banServer { return s }, true},
		{"no old tunnel, tunnel stays off", &SSHConnector{server: base}, func(s shared.Fail2banServer) shared.Fail2banServer { s.ReverseTunnelEnabled = false; return s }, false},
		{"tunnel disabled", tunneled, func(s shared.Fail2banServer) shared.Fail2banServer { s.ReverseTunnelEnabled = false; return s }, true},
		{"type changed", tunneled, func(s shared.Fail2banServer) shared.Fail2banServer { s.Type = "agent"; return s }, true},
		{"port changed", tunneled, func(s shared.Fail2banServer) shared.Fail2banServer { s.TunnelPort = 9444; return s }, true},
		{"host changed", tunneled, func(s shared.Fail2banServer) shared.Fail2banServer { s.Host = "10.0.0.2"; return s }, true},
		{"ssh user changed", tunneled, func(s shared.Fail2banServer) shared.Fail2banServer { s.SSHUser = "other"; return s }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sshTunnelConfigChanged(tc.old, tc.mutate(base)); got != tc.want {
				t.Fatalf("sshTunnelConfigChanged = %v, want %v", got, tc.want)
			}
		})
	}
}
