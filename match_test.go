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
