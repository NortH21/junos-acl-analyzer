package main

import (
	"net/netip"
	"testing"
)

func mustPrefixes(t *testing.T, items ...string) []netip.Prefix {
	t.Helper()
	var prefixes []netip.Prefix
	for _, item := range items {
		prefix, ok := parsePrefix(item)
		if !ok {
			t.Fatalf("bad prefix %q", item)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}

func TestParsePrefix(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{"10.1.1.5", "10.1.1.5/32", true},
		{" 10.1.1.0/24 ", "10.1.1.0/24", true},
		{"10.1.1.77/24", "10.1.1.0/24", true}, // биты хоста отбрасываются
		{"0.0.0.0/0", "0.0.0.0/0", true},
		{"2001:db8::1", "2001:db8::1/128", true},
		{"2001:db8::/32", "2001:db8::/32", true},
		{"", "", false},
		{"10.1.1", "", false},
		{"10.1.1.0/33", "", false},
		{"WEB", "", false},
		{"10.1.1.0/24 except", "", false},
	}
	for _, tt := range tests {
		got, ok := parsePrefix(tt.in)
		if ok != tt.ok || (ok && got.String() != tt.want) {
			t.Errorf("parsePrefix(%q) = %v, %v; want %s, %v", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}

func TestAddrSetMatch(t *testing.T) {
	plain := addrSet{constrained: true, nets: mustPrefixes(t, "10.1.1.0/24", "192.168.0.10/32")}
	withExcept := addrSet{
		constrained: true,
		nets:        mustPrefixes(t, "10.0.0.0/8", "10.9.1.0/24"),
		except:      mustPrefixes(t, "10.9.0.0/16"),
	}
	onlyExcept := addrSet{constrained: true, except: mustPrefixes(t, "10.9.0.0/16")}
	unresolved := addrSet{constrained: true}
	anyAddr := addrSet{}

	tests := []struct {
		name  string
		set   addrSet
		query string
		want  matchLevel
	}{
		{"host inside net", plain, "10.1.1.5", matchFull},
		{"host with mask", plain, "10.1.1.5/32", matchFull},
		{"exact net", plain, "10.1.1.0/24", matchFull},
		{"subnet of net", plain, "10.1.1.128/25", matchFull},
		{"supernet of net", plain, "10.1.0.0/16", matchPartial},
		{"host equal to /32", plain, "192.168.0.10", matchFull},
		{"neighbour host", plain, "192.168.0.11", matchNone},
		{"other net", plain, "10.1.2.0/24", matchNone},
		{"ipv6 against ipv4", plain, "2001:db8::1", matchNone},

		{"outside except", withExcept, "10.1.1.1", matchFull},
		{"inside except", withExcept, "10.9.5.5", matchNone},
		{"longer net wins over except", withExcept, "10.9.1.5", matchFull},
		{"query spans except", withExcept, "10.0.0.0/8", matchPartial},
		{"query inside except spans net", withExcept, "10.9.0.0/16", matchPartial},

		{"only except matches nothing", onlyExcept, "10.1.1.1", matchNone},
		{"unresolved list matches nothing", unresolved, "10.1.1.1", matchNone},
		{"no condition matches anything", anyAddr, "10.1.1.1", matchFull},

		{"no query, plain", plain, "", matchPartial},
		{"no query, unresolved", unresolved, "", matchNone},
		{"no query, no condition", anyAddr, "", matchFull},
	}
	for _, tt := range tests {
		query, hasQuery := parsePrefix(tt.query)
		if got := tt.set.match(query, hasQuery); got != tt.want {
			t.Errorf("%s: match(%q) = %d, want %d", tt.name, tt.query, got, tt.want)
		}
	}
}

func TestParsePortSpec(t *testing.T) {
	tests := []struct {
		in     string
		lo, hi int
		ok     bool
	}{
		{"443", 443, 443, true},
		{" 80 ", 80, 80, true},
		{"https", 443, 443, true},
		{"HTTPS", 443, 443, true},
		{"8080-8090", 8080, 8090, true},
		{"ftp-data", 20, 20, true},
		{"ftp-data-ftp", 20, 21, true},
		{"ssh-telnet", 22, 23, true},
		{"0", 0, 0, true},
		{"65535", 65535, 65535, true},
		{"65536", 0, 0, false},
		{"-1", 0, 0, false},
		{"90-80", 0, 0, false},
		{"abc", 0, 0, false},
		{"", 0, 0, false},
		{"80,443", 0, 0, false},
	}
	for _, tt := range tests {
		got, ok := parsePortSpec(tt.in)
		if ok != tt.ok || (ok && (got.lo != tt.lo || got.hi != tt.hi)) {
			t.Errorf("parsePortSpec(%q) = %v, %v; want {%d %d}, %v", tt.in, got, ok, tt.lo, tt.hi, tt.ok)
		}
	}
}

func TestPortSetMatch(t *testing.T) {
	ports := newPortSet([]string{"https", "8080-8090", "22"})
	withUnknown := newPortSet([]string{"80", "some-new-name"})
	anyPort := newPortSet(nil)

	tests := []struct {
		name  string
		set   portSet
		query string
		want  matchLevel
	}{
		{"number against name", ports, "443", matchFull},
		{"name against name", ports, "https", matchFull},
		{"name against number", ports, "ssh", matchFull},
		{"inside range", ports, "8085", matchFull},
		{"range inside range", ports, "8081-8089", matchFull},
		{"range edge", ports, "8090", matchFull},
		{"range overlapping range", ports, "8085-8100", matchPartial},
		{"range covering single port", ports, "20-25", matchPartial},
		{"outside", ports, "80", matchNone},
		{"range outside", ports, "9000-9100", matchNone},
		{"unknown value keeps a possible match", withUnknown, "8443", matchPartial},
		{"known value with unknown present", withUnknown, "80", matchFull},
		{"no condition", anyPort, "12345", matchFull},
		{"no query", ports, "", matchPartial},
		{"no query, no condition", anyPort, "", matchFull},
	}
	for _, tt := range tests {
		query, hasQuery := parsePortSpec(tt.query)
		if got := tt.set.match(query, hasQuery); got != tt.want {
			t.Errorf("%s: match(%q) = %d, want %d", tt.name, tt.query, got, tt.want)
		}
	}
}
