package main

import (
	"net/netip"
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
