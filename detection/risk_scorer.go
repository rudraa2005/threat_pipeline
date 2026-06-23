package detection

type Risk struct {
	Score    int
	Types    []string
	Tags     []string
	Severity string
}

func Scorer(matches []RuleMatch) Risk {
	score := 0

	types := make([]string, 0, len(matches))
	tags := make([]string, 0)

	seen := make(map[string]bool)
	for _, match := range matches {

		score += match.Severity
		types = append(types, match.RuleName)

		for _, tag := range match.Tags {
			if !seen[tag] {
				seen[tag] = true
				tags = append(tags, tag)
			}
		}
	}
	if len(matches) > 1 {
		score += 5 * (len(matches) - 1)
		score = min(score, 100)
	}
	severity := "LOW"
	switch {
	case score >= 90:
		severity = "CRITICAL"
	case score >= 70:
		severity = "HIGH"
	case score >= 40:
		severity = "MEDIUM"
	}
	return Risk{Score: score, Types: types, Tags: tags, Severity: severity}
}
