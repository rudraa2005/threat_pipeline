package detection

import (
	"regexp"
	"strings"
)

func New(rules []Rule) *RuleEngine {
	compiled := make([][]*regexp.Regexp, len(rules))

	for i, rule := range rules {
		compiled[i] = make([]*regexp.Regexp, len(rule.Patterns))
		for j, pattern := range rule.Patterns {
			if pattern.IsRegex {
				re, err := regexp.Compile(pattern.Value)
				if err != nil {
					return nil
				}
				compiled[i][j] = re
			}
		}
	}

	return &RuleEngine{rules: rules, compiled: compiled}
}

func (e *RuleEngine) Evaluate(text string) []RuleMatch {
	lower := strings.ToLower(text)
	var matches []RuleMatch

	for i, rule := range e.rules {
		var matchedPatterns []string

		for j, pattern := range rule.Patterns {
			re := e.compiled[i][j]

			if re != nil {
				if re.MatchString(text) {
					matchedPatterns = append(matchedPatterns, pattern.Value)
				}
			} else {
				if strings.Contains(lower, strings.ToLower(pattern.Value)) {
					matchedPatterns = append(matchedPatterns, pattern.Value)
				}
			}
		}
		if len(matchedPatterns) >= rule.Threshold {
			println(rule.Name, rule.Severity)

			matches = append(matches, RuleMatch{
				RuleName: rule.Name,
				Tags:     rule.Tags,
				Matched:  matchedPatterns,
				Severity: rule.Severity,
			})
		}
	}
	return matches
}
