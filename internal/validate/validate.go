// Package validate provides input normalization and validation shared by the
// client (for early feedback) and the daemon (as the authoritative check).
package validate

import (
	"fmt"
	"net"
	"strings"
)

// Limits guarding against abusive requests. The daemon enforces these
// authoritatively; the client may also use them for early rejection.
const (
	// MaxItemsPerRequest caps the number of domains or IPs in a single request.
	MaxItemsPerRequest = 256
	// MaxDomainLen is the maximum total length of a domain name (RFC 1035).
	MaxDomainLen = 253
	// MaxLabelLen is the maximum length of a single DNS label.
	MaxLabelLen = 63
)

// NormalizeDomain lowercases the input and strips a leading scheme, any path,
// userinfo, port, and a trailing dot, so that a user may paste a full URL such
// as "https://Example.com/path" and have it treated as "example.com".
func NormalizeDomain(in string) string {
	d := strings.TrimSpace(in)
	if d == "" {
		return ""
	}
	d = strings.ToLower(d)

	// Strip scheme.
	if i := strings.Index(d, "://"); i >= 0 {
		d = d[i+3:]
	}
	// Strip userinfo (user:pass@host).
	if i := strings.LastIndex(d, "@"); i >= 0 {
		d = d[i+1:]
	}
	// Strip path / query / fragment.
	for _, sep := range []string{"/", "?", "#"} {
		if i := strings.Index(d, sep); i >= 0 {
			d = d[:i]
		}
	}
	// Strip port, but be careful not to mangle IPv6 literals.
	if !strings.Contains(d, ":") || strings.Count(d, ":") == 1 {
		if i := strings.LastIndex(d, ":"); i >= 0 {
			d = d[:i]
		}
	}
	// Strip trailing dot (fully-qualified form).
	d = strings.TrimSuffix(d, ".")
	return d
}

// ValidateDomain returns an error if d is not a syntactically valid hostname.
// It does not resolve the domain. The input should already be normalized.
func ValidateDomain(d string) error {
	if d == "" {
		return fmt.Errorf("empty domain")
	}
	if len(d) > MaxDomainLen {
		return fmt.Errorf("domain %q exceeds %d characters", d, MaxDomainLen)
	}
	// A bare IP is not a domain; callers should pass IPs via the IP path.
	if net.ParseIP(d) != nil {
		return fmt.Errorf("%q is an IP address, use --ip instead", d)
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return fmt.Errorf("domain %q must have at least two labels", d)
	}
	for _, l := range labels {
		if err := validateLabel(l, d); err != nil {
			return err
		}
	}
	return nil
}

func validateLabel(l, d string) error {
	if l == "" {
		return fmt.Errorf("domain %q has an empty label", d)
	}
	if len(l) > MaxLabelLen {
		return fmt.Errorf("domain %q has a label longer than %d characters", d, MaxLabelLen)
	}
	if strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
		return fmt.Errorf("domain %q has a label that starts or ends with '-'", d)
	}
	for _, r := range l {
		isAlnum := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if !isAlnum && r != '-' {
			return fmt.Errorf("domain %q contains invalid character %q", d, r)
		}
	}
	return nil
}

// NormalizeIP validates and canonicalizes an IP address string. It returns the
// canonical form (as produced by net.IP.String) and whether it is IPv6.
func NormalizeIP(in string) (canonical string, isV6 bool, err error) {
	s := strings.TrimSpace(in)
	ip := net.ParseIP(s)
	if ip == nil {
		return "", false, fmt.Errorf("invalid IP address %q", in)
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String(), false, nil
	}
	return ip.String(), true, nil
}
