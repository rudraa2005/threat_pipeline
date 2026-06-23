package detection

import "regexp"

type Rule struct {
	Name      string
	Tags      []string
	Patterns  []Patterns
	Threshold int
	Severity  int
}

type Patterns struct {
	Value   string
	IsRegex bool
}

type RuleEngine struct {
	rules    []Rule
	compiled [][]*regexp.Regexp
}
type RuleMatch struct {
	RuleName string
	Tags     []string
	Matched  []string
	Severity int
}
