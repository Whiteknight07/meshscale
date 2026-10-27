package rules

import (
	"net/netip"
	"strings"
)

// Gateway removes redundant parentheses and host-length CIDR suffixes. Compare
// the small AND/OR expression grammar we emit, so a readback stays idempotent.
func canonicalExpression(s string) string {
	tokens := strings.Fields(strings.NewReplacer("(", " ( ", ")", " ) ", "{", " { ", "}", " } ").Replace(s))
	for i, token := range tokens {
		if p, err := netip.ParsePrefix(token); err == nil && p.Bits() == p.Addr().BitLen() {
			tokens[i] = p.Addr().String()
		}
	}
	p := expressionParser{tokens: tokens}
	root := p.parseOr()
	if root == nil || p.pos != len(tokens) {
		return "invalid:" + s
	}
	return root.key()
}

type expression struct {
	op       string
	children []*expression
}

func (e *expression) key() string {
	if len(e.children) == 0 {
		return e.op
	}
	var parts []string
	var appendChild func(*expression)
	appendChild = func(child *expression) {
		if child.op == e.op && len(child.children) > 0 {
			for _, c := range child.children {
				appendChild(c)
			}
		} else {
			parts = append(parts, child.key())
		}
	}
	for _, c := range e.children {
		appendChild(c)
	}
	return "(" + e.op + " " + strings.Join(parts, " ") + ")"
}

type expressionParser struct {
	tokens []string
	pos    int
}

func (p *expressionParser) take(s string) bool {
	if p.pos < len(p.tokens) && p.tokens[p.pos] == s {
		p.pos++
		return true
	}
	return false
}
func (p *expressionParser) parseOr() *expression {
	left := p.parseAnd()
	for p.take("or") {
		right := p.parseAnd()
		if left == nil || right == nil {
			return nil
		}
		left = &expression{op: "or", children: []*expression{left, right}}
	}
	return left
}
func (p *expressionParser) parseAnd() *expression {
	left := p.parseAtom()
	for p.take("and") {
		right := p.parseAtom()
		if left == nil || right == nil {
			return nil
		}
		left = &expression{op: "and", children: []*expression{left, right}}
	}
	return left
}
func (p *expressionParser) parseAtom() *expression {
	if p.take("(") {
		e := p.parseOr()
		if !p.take(")") {
			return nil
		}
		return e
	}
	start := p.pos
	for p.pos < len(p.tokens) {
		token := p.tokens[p.pos]
		if token == "(" || token == ")" || token == "and" || token == "or" {
			break
		}
		p.pos++
	}
	if start == p.pos {
		return nil
	}
	return &expression{op: strings.Join(p.tokens[start:p.pos], " ")}
}
