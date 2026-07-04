package validate

import "testing"

func TestNormalizeDomain(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"Example.com", "example.com"},
		{"https://Example.com/path", "example.com"},
		{"http://user:pass@host.com:80", "host.com"},
		{"sub.example.com.", "sub.example.com"},
		{"  ads.example.net  ", "ads.example.net"},
		{"example.com/a/b?q=1#frag", "example.com"},
	}
	for _, c := range cases {
		if got := NormalizeDomain(c.in); got != c.want {
			t.Errorf("NormalizeDomain(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestValidateDomain(t *testing.T) {
	valid := []string{"example.com", "a.b.c.example.co.uk", "x-y.example.com"}
	for _, d := range valid {
		if err := ValidateDomain(d); err != nil {
			t.Errorf("ValidateDomain(%q) unexpected error: %v", d, err)
		}
	}

	// Each is invalid for a distinct reason: empty, single label, leading and
	// trailing hyphen labels, invalid character, and a bare IP.
	invalid := []string{
		"",
		"singlelabel",
		"-bad.example.com",
		"bad-.example.com",
		"under_score.com",
		"1.2.3.4",
	}
	for _, d := range invalid {
		if err := ValidateDomain(d); err == nil {
			t.Errorf("ValidateDomain(%q) expected error, got nil", d)
		}
	}
}

func TestNormalizeIP(t *testing.T) {
	v4, isV6, err := NormalizeIP("93.184.216.34")
	if err != nil || isV6 || v4 != "93.184.216.34" {
		t.Errorf("v4 parse: got (%q,%v,%v)", v4, isV6, err)
	}

	v6, isV6, err := NormalizeIP("2001:db8::1")
	if err != nil || !isV6 || v6 != "2001:db8::1" {
		t.Errorf("v6 parse: got (%q,%v,%v)", v6, isV6, err)
	}

	if _, _, err := NormalizeIP("not-an-ip"); err == nil {
		t.Errorf("expected error for invalid IP")
	}
}
