package main

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Запрос на проверку доступа. Незаполненное поле означает "любое значение"
type accessQuery struct {
	src, dst       netip.Prefix
	hasSrc, hasDst bool
	port           portRange
	hasPort        bool
}

// Результат проверки доступа
type accessResult struct {
	Allowed []GroupedRule // accept-термы, до которых запрос может дойти
	Blocked []GroupedRule // запрещающие термы, которые перехватывают запрос целиком
}

// Терм, совпавший с запросом
type matchedRule struct {
	rule       *PolicyRule
	shadowedBy []string // более ранние запрещающие термы, которые могут перехватить трафик
}

// Разбирает поля формы проверки
func parseAccessQuery(src, dst, port string) (accessQuery, error) {
	var query accessQuery
	var ok bool

	if src = strings.TrimSpace(src); src != "" {
		if query.src, ok = parsePrefix(src); !ok {
			return query, fmt.Errorf("invalid source address or network: %q", src)
		}
		query.hasSrc = true
	}
	if dst = strings.TrimSpace(dst); dst != "" {
		if query.dst, ok = parsePrefix(dst); !ok {
			return query, fmt.Errorf("invalid destination address or network: %q", dst)
		}
		query.hasDst = true
	}
	if port = strings.TrimSpace(port); port != "" {
		if query.port, ok = parsePortSpec(port); !ok {
			return query, fmt.Errorf("invalid port or port range: %q", port)
		}
		query.hasPort = true
	}

	return query, nil
}

// Есть ли в терме условия, которые анализатор не проверяет
func (r *PolicyRule) hasUncheckedConditions() bool {
	return r.Term.Protocol != "" || len(r.Term.SourcePorts) > 0 || len(r.Term.OtherConditions) > 0
}

// Сопоставляет терм с запросом
func (r *PolicyRule) match(query accessQuery) matchLevel {
	level := min(
		r.srcAddrs.match(query.src, query.hasSrc),
		r.dstAddrs.match(query.dst, query.hasDst),
		r.dstPorts.match(query.port, query.hasPort),
	)

	// Протокол, source-port и прочие условия в запросе не задаются,
	// поэтому терм с ними покрывает запрос только частично
	if level == matchFull && r.hasUncheckedConditions() {
		return matchPartial
	}
	return level
}

// Проверяет доступ по всем фильтрам. Каждый фильтр обрабатывается отдельно
// и по порядку термов, как это делает Junos
func checkAccess(state *AppState, query accessQuery, filter string) accessResult {
	var allowed, blocked []matchedRule

	rules := state.PolicyRules
	for start := 0; start < len(rules); {
		// Термы одного фильтра идут подряд
		end := start + 1
		for end < len(rules) && rules[end].FilterName == rules[start].FilterName && rules[end].Source == rules[start].Source {
			end++
		}

		if filter == "" || rules[start].FilterName == filter {
			filterAllowed, filterBlocked := evaluateFilter(rules[start:end], query)
			allowed = append(allowed, filterAllowed...)
			blocked = append(blocked, filterBlocked...)
		}
		start = end
	}

	return accessResult{
		Allowed: groupRules(allowed),
		Blocked: groupRules(blocked),
	}
}

// Проходит термы фильтра по порядку (first match). Терм, который покрывает
// запрос целиком, останавливает обработку: до следующих термов трафик не дойдет.
// В конце фильтра действует неявный discard
func evaluateFilter(terms []PolicyRule, query accessQuery) (allowed, blocked []matchedRule) {
	var earlierDeny []*PolicyRule

	for i := range terms {
		term := &terms[i]

		level := term.match(query)
		if level == matchNone {
			continue
		}

		switch term.Term.Action {
		case "next":
			// "next term" не принимает решения
			continue

		case "accept":
			match := matchedRule{rule: term}
			for _, deny := range earlierDeny {
				if termsOverlap(deny, term, query) {
					match.shadowedBy = append(match.shadowedBy, deny.Term.Name)
				}
			}
			allowed = append(allowed, match)

		default:
			// reject и discard
			if level == matchFull {
				blocked = append(blocked, matchedRule{rule: term})
				return allowed, blocked
			}
			earlierDeny = append(earlierDeny, term)
		}

		if level == matchFull {
			return allowed, blocked
		}
	}

	return allowed, blocked
}

// Могут ли два терма совпасть на одном и том же трафике в рамках запроса.
// Заданные в запросе поля уже совпали с обоими термами, проверяем остальные
func termsOverlap(a, b *PolicyRule, query accessQuery) bool {
	if !query.hasSrc && !addrSetsOverlap(a.srcAddrs, b.srcAddrs) {
		return false
	}
	if !query.hasDst && !addrSetsOverlap(a.dstAddrs, b.dstAddrs) {
		return false
	}
	if !query.hasPort && !portSetsOverlap(a.dstPorts, b.dstPorts) {
		return false
	}
	return protocolsOverlap(a.Term.Protocol, b.Term.Protocol)
}

func addrSetsOverlap(a, b addrSet) bool {
	if !a.constrained || !b.constrained {
		return true
	}
	for _, x := range a.nets {
		for _, y := range b.nets {
			if x.Overlaps(y) {
				return true
			}
		}
	}
	return false
}

func portSetsOverlap(a, b portSet) bool {
	if !a.constrained || !b.constrained || a.unknown || b.unknown {
		return true
	}
	for _, x := range a.ranges {
		for _, y := range b.ranges {
			if x.lo <= y.hi && y.lo <= x.hi {
				return true
			}
		}
	}
	return false
}

// Сравнивает условия protocol: "tcp", "[ tcp udp ]"
func protocolsOverlap(a, b string) bool {
	if a == "" || b == "" {
		return true
	}
	for _, x := range parsePortRange(a) {
		for _, y := range parsePortRange(b) {
			if x == y {
				return true
			}
		}
	}
	return false
}

// Группирует одинаковые термы из разных фильтров в одну карточку.
// Термы считаются одинаковыми, только если совпадают все их условия
func groupRules(matches []matchedRule) []GroupedRule {
	groupedRules := make(map[string]*GroupedRule)

	for _, match := range matches {
		rule := match.rule
		shadowedBy := uniqueStrings(match.shadowedBy)

		key := fmt.Sprintf("%q|%q|%q|%q|%q|%q|%q|%q|%q|%q|%q",
			rule.Term.Name,
			sortedSlice(rule.Term.SourceAddresses),
			sortedSlice(rule.Term.DestinationAddresses),
			sortedSlice(rule.Term.SourcePrefixLists),
			sortedSlice(rule.Term.DestinationPrefixLists),
			rule.Term.Protocol,
			sortedSlice(rule.Term.SourcePorts),
			sortedSlice(rule.Term.DestinationPorts),
			sortedSlice(rule.Term.OtherConditions),
			rule.Term.Action,
			sortedSlice(shadowedBy))

		if groupedRule, exists := groupedRules[key]; !exists {
			groupedRules[key] = &GroupedRule{
				TermName:               rule.Term.Name,
				SourcePrefixes:         uniqueStrings(rule.ResolvedSourcePrefixes),
				DestinationPrefixes:    uniqueStrings(rule.ResolvedDestinationPrefixes),
				SourcePrefixLists:      uniqueStrings(rule.Term.SourcePrefixLists),
				DestinationPrefixLists: uniqueStrings(rule.Term.DestinationPrefixLists),
				Protocol:               rule.Term.Protocol,
				SourcePorts:            uniqueStrings(rule.Term.SourcePorts),
				DestinationPorts:       uniqueStrings(rule.Term.DestinationPorts),
				OtherConditions:        uniqueStrings(rule.Term.OtherConditions),
				Action:                 rule.Term.Action,
				Filters:                []string{rule.FilterName},
				ShadowedBy:             shadowedBy,
			}
		} else if !containsString(groupedRule.Filters, rule.FilterName) {
			groupedRule.Filters = append(groupedRule.Filters, rule.FilterName)
		}
	}

	// Конвертируем map в slice и сортируем по имени term
	result := make([]GroupedRule, 0, len(groupedRules))
	for _, rule := range groupedRules {
		sort.Strings(rule.Filters)
		result = append(result, *rule)
	}

	sort.SliceStable(result, func(i, j int) bool {
		if result[i].TermName != result[j].TermName {
			return result[i].TermName < result[j].TermName
		}
		return strings.Join(result[i].Filters, ",") < strings.Join(result[j].Filters, ",")
	})

	return result
}
