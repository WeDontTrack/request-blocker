// Command webblock is the unprivileged CLI client. It parses the user's request
// and forwards it to the webblockd daemon over a Unix socket. It holds no
// privileges of its own; all enforcement happens in the daemon.
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"webblock/internal/proto"
	"webblock/internal/validate"
)

// clientVersion is the human-facing CLI version. The wire compatibility version
// is proto.Version.
const clientVersion = "0.2.0"

const usage = `webblock - block websites and IPs on Linux

Usage:
  webblock --add    [--name <d1>,<d2>] [--ip <ip1>,<ip2>] [--user <name|uid>]
  webblock --remove [--name <d1>,<d2>] [--ip <ip1>,<ip2>] [--user <name|uid>]
  webblock --show   [--json]
  webblock --status [--json]
  webblock --version

Scope:
  Run as root to manage the global blocklist (applies to all users), or pass
  --user to target a specific user's list. Run as a normal user to manage only
  your own blocklist.

Examples:
  webblock --add --name example.com,ads.example.net
  webblock --add --ip 93.184.216.34
  webblock --add --name tracker.com --ip 10.0.0.5
  webblock --remove --name example.com
  webblock --show
  webblock --show --json
`

type options struct {
	add, remove, show, status bool
	jsonOut                   bool
	name, ip, user            string
	socket                    string
}

func main() {
	opts, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		fmt.Fprint(os.Stderr, "\n", usage)
		os.Exit(2)
	}

	req, err := buildRequest(opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	resp, err := send(opts.socket, req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	if !resp.OK {
		fmt.Fprintln(os.Stderr, "error:", resp.Error)
		os.Exit(1)
	}

	render(req.Action, opts.jsonOut, resp)
}

// parseArgs is a small hand-rolled parser so we can accept the GNU-style
// "--flag value" and "--flag=value" forms exactly as described in the plan.
func parseArgs(args []string) (options, error) {
	o := options{socket: proto.SocketPath}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--add":
			o.add = true
		case "--remove":
			o.remove = true
		case "--show":
			o.show = true
		case "--status":
			o.status = true
		case "--json":
			o.jsonOut = true
		case "--version":
			fmt.Printf("webblock %s (protocol %d)\n", clientVersion, proto.Version)
			os.Exit(0)
		case "-h", "--help":
			fmt.Print(usage)
			os.Exit(0)
		case "--name", "--ip", "--user", "--socket":
			i++
			if i >= len(args) {
				return o, fmt.Errorf("%s requires a value", a)
			}
			switch a {
			case "--name":
				o.name = args[i]
			case "--ip":
				o.ip = args[i]
			case "--user":
				o.user = args[i]
			case "--socket":
				o.socket = args[i]
			}
		default:
			if k, v, ok := splitEq(a); ok {
				switch k {
				case "--name":
					o.name = v
				case "--ip":
					o.ip = v
				case "--user":
					o.user = v
				case "--socket":
					o.socket = v
				default:
					return o, fmt.Errorf("unknown flag %q", k)
				}
				continue
			}
			return o, fmt.Errorf("unknown argument %q", a)
		}
	}
	return o, validateActions(o)
}

// validateActions ensures exactly one action is selected and that read-only
// actions are not mixed with mutation arguments.
func validateActions(o options) error {
	n := 0
	for _, b := range []bool{o.add, o.remove, o.show, o.status} {
		if b {
			n++
		}
	}
	if n == 0 {
		return fmt.Errorf("specify exactly one of --add, --remove, --show, or --status")
	}
	if n > 1 {
		return fmt.Errorf("--add, --remove, --show, and --status are mutually exclusive")
	}
	if (o.show || o.status) && (o.name != "" || o.ip != "" || o.user != "") {
		return fmt.Errorf("--show/--status take no --name/--ip/--user arguments")
	}
	return nil
}

func splitEq(a string) (key, val string, ok bool) {
	if !strings.HasPrefix(a, "--") {
		return "", "", false
	}
	if i := strings.Index(a, "="); i >= 0 {
		return a[:i], a[i+1:], true
	}
	return "", "", false
}

func buildRequest(o options) (proto.Request, error) {
	req := proto.Request{Version: proto.Version, TargetUser: o.user}
	switch {
	case o.show:
		req.Action = proto.ActionShow
		return req, nil
	case o.status:
		req.Action = proto.ActionStatus
		return req, nil
	case o.add:
		req.Action = proto.ActionAdd
	case o.remove:
		req.Action = proto.ActionRemove
	}

	domains, err := cleanDomains(o.name)
	if err != nil {
		return req, err
	}
	ips, err := cleanIPs(o.ip)
	if err != nil {
		return req, err
	}
	if len(domains) == 0 && len(ips) == 0 {
		return req, fmt.Errorf("provide --name and/or --ip")
	}
	req.Domains = domains
	req.IPs = ips
	return req, nil
}

func cleanDomains(csv string) ([]string, error) {
	var out []string
	for _, raw := range splitList(csv) {
		d := validate.NormalizeDomain(raw)
		if err := validate.ValidateDomain(d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

func cleanIPs(csv string) ([]string, error) {
	var out []string
	for _, raw := range splitList(csv) {
		canon, _, err := validate.NormalizeIP(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, canon)
	}
	return out, nil
}

func splitList(csv string) []string {
	if strings.TrimSpace(csv) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(csv, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func send(socket string, req proto.Request) (proto.Response, error) {
	var resp proto.Response
	conn, err := net.DialTimeout("unix", socket, 5*time.Second)
	if err != nil {
		return resp, fmt.Errorf("cannot reach webblockd at %s (is the service running?): %w", socket, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	data, err := json.Marshal(req)
	if err != nil {
		return resp, err
	}
	if _, err := conn.Write(append(data, '\n')); err != nil {
		return resp, fmt.Errorf("send failed: %w", err)
	}
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return resp, fmt.Errorf("no/invalid response from daemon: %w", err)
	}
	return resp, nil
}

func render(action proto.Action, jsonOut bool, resp proto.Response) {
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(resp)
		return
	}

	switch action {
	case proto.ActionStatus:
		if resp.Status != nil {
			fmt.Printf("daemon OK\n  backend:          %s\n  protocol version: %d\n", resp.Status.Backend, resp.Status.ProtocolVersion)
		}
	case proto.ActionShow:
		renderViews(resp.Views)
	default:
		fmt.Println(resp.Message)
	}
}

func renderViews(views []proto.ScopeView) {
	if len(views) == 0 {
		fmt.Println("no blocklists configured")
		return
	}
	for _, v := range views {
		header := v.Scope
		if v.ReadOnly {
			header += " [read-only]"
		}
		fmt.Printf("== %s ==\n", header)
		if len(v.Domains) == 0 && len(v.IPs) == 0 {
			fmt.Println("  (empty)")
		}
		for _, d := range v.Domains {
			fmt.Printf("  domain  %s\n", d)
		}
		for _, ip := range v.IPs {
			fmt.Printf("  ip      %s\n", ip)
		}
		fmt.Println()
	}
}
