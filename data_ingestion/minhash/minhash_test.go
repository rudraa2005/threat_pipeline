package minhash

import "testing"

func TestMinHashEstimatesJaccard(t *testing.T) {
	m := New(200) // 200 hashes = better accuracy

	cases := []struct {
		a, b       string
		minJ, maxJ float64 // expected Jaccard range
	}{
		{
			"threat actors exploiting power grid infrastructure using malware",
			"threat actors exploiting power grid infrastructure using malware",
			0.95, 1.0, // identical = Jaccard 1.0
		},
		{
			"ransomware campaign targeting healthcare sector with phishing",
			"ransomware attack against healthcare organizations via phishing emails",
			0.2, 0.6, // similar but not identical
		},
		{
			"apt group using zero day exploit in windows kernel",
			"weather forecast shows rain in mumbai tomorrow morning",
			0.0, 0.1, // completely unrelated
		},
	}

	for _, c := range cases {
		sigA := m.Signature(c.a)
		sigB := m.Signature(c.b)
		est := EstimateJaccard(sigA, sigB)
		if est < c.minJ || est > c.maxJ {
			t.Errorf("jaccard estimate %.3f outside [%.2f, %.2f]\nA: %s\nB: %s",
				est, c.minJ, c.maxJ, c.a, c.b)
		}
		t.Logf("jaccard estimate: %.3f for pair", est)
	}
}

func TestJaccardEstimate(t *testing.T) {
	msh := New(200)
	sigA := msh.Signature("ransomware actors exploiting critical infrastructure using malicious payloads")
	sigB := msh.Signature("ransomware group exploiting critical infrastructure using malicious tools")
	j := EstimateJaccard(sigA, sigB)
	t.Logf("jaccard estimate: %.3f", j)
}
