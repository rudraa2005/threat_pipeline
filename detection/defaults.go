package detection

var DefaultRules = []Rule{
	{
		Name: "Ransomware_Generic",
		Tags: []string{"ransomware:high"},
		Patterns: []Patterns{
			{Value: "encrypted", IsRegex: false},
			{Value: "ransom", IsRegex: false},
			{Value: "decryption key", IsRegex: false},
			{Value: "pay within", IsRegex: false},
		},
		Threshold: 1,
		Severity:  30,
	},
	{
		Name: "credential_leak",
		Tags: []string{"credential_leak:high"},
		Patterns: []Patterns{
			{Value: `(^|[^A-Z0-9])[A-Z0-9]{20}([^A-Z0-9]|$)`, IsRegex: true},
			{Value: `(?i)aws(.{0,20})?['"][0-9a-zA-Z\/+]{40}['"]`, IsRegex: true},
			{Value: `github_pat_[0-9a-zA-Z_]{82}`, IsRegex: true},
			{Value: `https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8}\/B[A-Z0-9]{8}\/[A-Za-z0-9]{24}`, IsRegex: true},
			{Value: `AIza[0-9A-Za-z-_]{35}`, IsRegex: true},
			{Value: `(?i)bearer\s+[A-Za-z0-9\-._~+\/]+=*`, IsRegex: true},
		},
		Threshold: 1,
		Severity:  40,
	},
	{
		Name: "data_exfiltration",
		Tags: []string{"data_leaked:high"},
		Patterns: []Patterns{
			{Value: `\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b`, IsRegex: true},
			{Value: `\b\d{3}-\d{2}-\d{4}\b`, IsRegex: true},
			{Value: "INSERT INTO `", IsRegex: false},
			{Value: "CREATE TABLE `", IsRegex: false},
			{Value: `\b[a-zA-Z0-9_-]{50,}\.[a-zA-Z0-9_-]+\.(?:com|net|org|biz|xyz)\b`, IsRegex: true},
			{Value: `\beyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\b`, IsRegex: true},
		},
		Threshold: 1,
		Severity:  50,
	},
	{
		Name: "cve_exploitation",
		Tags: []string{"cve_exploitation:high"},
		Patterns: []Patterns{
			{Value: `\$\{(?i:jndi):(?i:ldap|rmi|ldaps|dns):`, IsRegex: true},
			{Value: `(?:\.\.\/|\.\.\\)+etc/passwd`, IsRegex: true},
			{Value: `(?:\.\.\/|\.\.\\)+windows/win\.ini`, IsRegex: true},
			{Value: `(?i)(x' OR '1'='1|' OR 1=1|' --|' UNION SELECT)`, IsRegex: true},
			{Value: "class.module.classLoader.resources.context", IsRegex: false},
		},
		Threshold: 1,
		Severity:  60,
	},
	{
		Name: "phishing_vectors",
		Tags: []string{"phishing:high"},
		Patterns: []Patterns{
			{Value: "action required: verify your account", IsRegex: false},
			{Value: "urgent: suspicious account activity", IsRegex: false},
			{Value: `(?i)href\s*=\s*['"][^'"]*\/login\.(?:php|html|asp)\b`, IsRegex: true},
			{Value: `(?i)(micros0ft|sec-login-|verify-paypal|accounts-google)`, IsRegex: true},
			{Value: `\b(?:bit\.ly|tinyurl\.com|t\.co|cutt\.ly)\/[a-zA-Z0-9_-]+`, IsRegex: true},
		},
		Threshold: 1,
		Severity:  80,
	},
}
