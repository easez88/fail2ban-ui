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
	"errors"
	"strings"
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

const sshMuxNoise = "mux_client_request_session: session request failed: Session open refused by peer\r\n" +
	"ControlSocket /tmp/ssh_control_srv-04e7c5bf2beffe52_172_16_10_13 already exists, disabling multiplexing\n"

func TestSelectCommandOutput(t *testing.T) {
	jailFile := "[swissmakers-apache-scanner]\nenabled = true\n"

	t.Run("success returns stdout only, stderr noise dropped", func(t *testing.T) {
		out, err := selectCommandOutput(jailFile, sshMuxNoise, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if strings.Contains(out, "mux_client_request_session") || strings.Contains(out, "ControlSocket") {
			t.Fatalf("stderr noise leaked into output: %q", out)
		}
		if out != strings.TrimSpace(jailFile) {
			t.Fatalf("output = %q, want trimmed stdout", out)
		}
	})

	t.Run("failure folds both streams into the error", func(t *testing.T) {
		out, err := selectCommandOutput("partial", "sudo: a password is required", errors.New("exit status 1"))
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "sudo: a password is required") || !strings.Contains(err.Error(), "partial") {
			t.Fatalf("error should contain both streams, got: %v", err)
		}
		if !strings.Contains(out, "sudo: a password is required") {
			t.Fatalf("returned output should keep error-path matching working, got: %q", out)
		}
	})
}

func TestBuildRemoteWriteScript(t *testing.T) {
	t.Run("single quotes are preserved verbatim", func(t *testing.T) {
		content := `ignoreregex = [^"]*(?:Let's Encrypt|Uptime)[^"]*` + "\n"
		script, err := buildRemoteWriteScript("/etc/fail2ban/filter.d/test.local", content)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(script, "Let's Encrypt") {
			t.Fatalf("content was altered: %q", script)
		}
		if strings.Contains(script, `'"'"'`) {
			t.Fatalf("content must not be shell-escaped inside a quoted heredoc: %q", script)
		}
	})

	t.Run("delimiter collision is rejected", func(t *testing.T) {
		if _, err := buildRemoteWriteScript("/tmp/f", "a\n"+remoteWriteDelimiter+"\nb\n"); err == nil {
			t.Fatal("expected error for content containing the heredoc delimiter")
		}
	})

	t.Run("unsafe path is rejected", func(t *testing.T) {
		if _, err := buildRemoteWriteScript("/tmp/f'oo", "x\n"); err == nil {
			t.Fatal("expected error for path containing a single quote")
		}
	})

	t.Run("exactly one trailing newline", func(t *testing.T) {
		script, err := buildRemoteWriteScript("/tmp/f", "line1\nline2\n")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := "cat > '/tmp/f' <<'" + remoteWriteDelimiter + "'\nline1\nline2\n" + remoteWriteDelimiter + "\n"
		if script != want {
			t.Fatalf("script = %q, want %q", script, want)
		}
	})
}

func TestParseLogpathProbe(t *testing.T) {
	t.Run("NOACCESS marker -> inaccessible sentinel", func(t *testing.T) {
		_, err := parseLogpathProbe(logpathMarkerNoAccess + "\n")
		if !errors.Is(err, ErrLogpathInaccessible) {
			t.Fatalf("want ErrLogpathInaccessible, got %v", err)
		}
	})
	t.Run("NODIR marker -> empty, no error", func(t *testing.T) {
		files, err := parseLogpathProbe(logpathMarkerNoDir + "\n")
		if err != nil || len(files) != 0 {
			t.Fatalf("want empty/no-error, got files=%v err=%v", files, err)
		}
	})
	t.Run("file list parsed", func(t *testing.T) {
		files, err := parseLogpathProbe("/var/log/httpd/access_log\n/var/log/httpd/ssl_access_log\n")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(files) != 2 || files[0] != "/var/log/httpd/access_log" {
			t.Fatalf("unexpected files: %v", files)
		}
	})
	t.Run("empty output -> no files, no error", func(t *testing.T) {
		files, err := parseLogpathProbe("\n  \n")
		if err != nil || len(files) != 0 {
			t.Fatalf("want empty/no-error, got files=%v err=%v", files, err)
		}
	})
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
