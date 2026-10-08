package main

import (
	"net/netip"
	"strconv"
	"strings"
)

// Степень совпадения условия с запросом
type matchLevel int

const (
	matchNone    matchLevel = iota // под условие не попадает ничего из запроса
	matchPartial                   // под условие попадает часть запроса
	matchFull                      // под условие попадает весь запрос
)

// Адресное условие терма: префиксы и исключения (except)
type addrSet struct {
	constrained bool // в терме есть условие по адресу, даже если оно ни во что не развернулось
	nets        []netip.Prefix
	except      []netip.Prefix
}

// Разбирает адрес ("10.0.0.1") или префикс ("10.0.0.0/8")
func parsePrefix(s string) (netip.Prefix, bool) {
	s = strings.TrimSpace(s)

	if strings.Contains(s, "/") {
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, false
		}
		return prefix.Masked(), true
	}

	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, false
	}
	addr = addr.WithZone("")
	return netip.PrefixFrom(addr, addr.BitLen()), true
}

// Проверяет, что inner целиком лежит внутри outer
func prefixContains(outer, inner netip.Prefix) bool {
	return outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}

// Сопоставляет запрос с адресным условием. Как и в Junos, решает самый
// длинный совпавший префикс: если это except, адрес под условие не попадает
func (a addrSet) match(query netip.Prefix, hasQuery bool) matchLevel {
	if !a.constrained {
		return matchFull
	}
	if !hasQuery {
		if len(a.nets) == 0 {
			return matchNone
		}
		return matchPartial
	}

	best, bestIsExcept := -1, false
	inner, innerExcept := false, false

	for _, net := range a.nets {
		switch {
		case prefixContains(net, query):
			if net.Bits() > best {
				best, bestIsExcept = net.Bits(), false
			}
		case prefixContains(query, net):
			inner = true
		}
	}
	for _, net := range a.except {
		switch {
		case prefixContains(net, query):
			if net.Bits() >= best {
				best, bestIsExcept = net.Bits(), true
			}
		case prefixContains(query, net):
			innerExcept = true
		}
	}

	if best >= 0 && !bestIsExcept {
		if innerExcept {
			return matchPartial
		}
		return matchFull
	}
	if inner {
		return matchPartial
	}
	return matchNone
}

// Проверяет пересечение запроса с любым префиксом условия (для поиска)
func (a addrSet) overlaps(query netip.Prefix) bool {
	for _, net := range a.nets {
		if net.Overlaps(query) {
			return true
		}
	}
	for _, net := range a.except {
		if net.Overlaps(query) {
			return true
		}
	}
	return false
}

// Именованные порты Junos (match conditions destination-port/source-port)
var namedPorts = map[string]int{
	"afs": 1483, "bgp": 179, "biff": 512, "bootpc": 68, "bootps": 67,
	"cmd": 514, "cvspserver": 2401, "dhcp": 67, "domain": 53, "eklogin": 2105,
	"ekshell": 2106, "exec": 512, "finger": 79, "ftp": 21, "ftp-data": 20,
	"http": 80, "https": 443, "ident": 113, "imap": 143, "kerberos-sec": 88,
	"klogin": 543, "kpasswd": 761, "krb-prop": 754, "krbupdate": 760, "kshell": 544,
	"ldap": 389, "ldp": 646, "login": 513, "mobileip-agent": 434, "mobilip-mn": 435,
	"msdp": 639, "netbios-dgm": 138, "netbios-ns": 137, "netbios-ssn": 139, "nfsd": 2049,
	"nntp": 119, "ntalk": 518, "ntp": 123, "pop3": 110, "pptp": 1723,
	"printer": 515, "radacct": 1813, "radius": 1812, "rip": 520, "rkinit": 2108,
	"smtp": 25, "snmp": 161, "snmptrap": 162, "snpp": 444, "socks": 1080,
	"ssh": 22, "sunrpc": 111, "syslog": 514, "tacacs": 49, "tacacs-ds": 65,
	"talk": 517, "telnet": 23, "tftp": 69, "timed": 525, "who": 513,
	"xdmcp": 177, "zephyr-clt": 2103, "zephyr-hm": 2104,
}

// Диапазон портов, границы включительно
type portRange struct {
	lo, hi int
}

// Условие терма по портам
type portSet struct {
	constrained bool // в терме есть условие по порту
	ranges      []portRange
	unknown     bool // часть значений разобрать не удалось
}

// Разбирает один порт: число или имя
func parsePort(s string) (int, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if port, ok := namedPorts[s]; ok {
		return port, true
	}

	port, err := strconv.Atoi(s)
	if err != nil || port < 0 || port > 65535 {
		return 0, false
	}
	return port, true
}

// Разбирает порт или диапазон: "443", "https", "8080-8090", "ftp-data-ftp"
func parsePortSpec(s string) (portRange, bool) {
	s = strings.TrimSpace(s)
	if port, ok := parsePort(s); ok {
		return portRange{port, port}, true
	}

	// В именах портов тоже есть дефис, поэтому пробуем каждый как разделитель
	for i := 0; i < len(s); i++ {
		if s[i] != '-' {
			continue
		}
		lo, okLo := parsePort(s[:i])
		hi, okHi := parsePort(s[i+1:])
		if okLo && okHi && lo <= hi {
			return portRange{lo, hi}, true
		}
	}
	return portRange{}, false
}

func newPortSet(specs []string) portSet {
	ports := portSet{constrained: len(specs) > 0}
	for _, spec := range specs {
		if r, ok := parsePortSpec(spec); ok {
			ports.ranges = append(ports.ranges, r)
		} else {
			ports.unknown = true
		}
	}
	return ports
}

// Сопоставляет порт или диапазон из запроса с условием терма
func (p portSet) match(query portRange, hasQuery bool) matchLevel {
	if !p.constrained {
		return matchFull
	}
	if !hasQuery {
		return matchPartial
	}

	level := matchNone
	for _, r := range p.ranges {
		if r.lo <= query.lo && query.hi <= r.hi {
			return matchFull
		}
		if r.lo <= query.hi && query.lo <= r.hi {
			level = matchPartial
		}
	}

	// Неразобранное значение могло бы совпасть, поэтому не утверждаем обратное
	if level == matchNone && p.unknown {
		return matchPartial
	}
	return level
}
