package extractor

import (
	"context"
	"strings"
	"testing"
	"threat_pipeline/crawler/client"
	"threat_pipeline/crawler/fetcher"
	"time"
)

func TestExtractTextBasic(t *testing.T) {
	raw := []byte(`
        <html>
            <body>
                <h1>Ransomware Alert</h1>
                <p>A new threat actor group has been identified.</p>
            </body>
        </html>
    `)

	text, err := ExtractText(raw, 5*1024*1024)
	if err != nil {
		t.Fatalf("extraction failed: %v", err)
	}

	if !strings.Contains(text, "Ransomware Alert") {
		t.Fatalf("missing expected text, got: %s", text)
	}
	if !strings.Contains(text, "threat actor group") {
		t.Fatalf("missing expected text, got: %s", text)
	}
	t.Logf("extracted: %s", text)
}

func TestExtractTextSkipsScripts(t *testing.T) {
	raw := []byte(`
        <html>
            <body>
                <p>Visible content here.</p>
                <script>var secret = "should not appear";</script>
                <style>.hidden { display: none; }</style>
            </body>
        </html>
    `)

	text, err := ExtractText(raw, 5*1024*1024)
	if err != nil {
		t.Fatalf("extraction failed: %v", err)
	}

	if strings.Contains(text, "secret") {
		t.Fatalf("script content leaked into extracted text: %s", text)
	}
	if strings.Contains(text, "hidden") {
		t.Fatalf("style content leaked into extracted text: %s", text)
	}
	if !strings.Contains(text, "Visible content here") {
		t.Fatalf("missing expected visible text: %s", text)
	}
	t.Logf("extracted: %s", text)
}

func TestExtractTextRealWorld(t *testing.T) {
	// fetch a real page and extract its text, eyeball the output
	c := client.NewClearnet()
	f := fetcher.New(c)

	result, err := f.Fetch("https://httpbin.org/html", context.Background())
	if err != nil {
		t.Fatalf("fetch failed: %v", err)
	}

	text, err := ExtractText([]byte(result.Body), 5*1024*1024)
	if err != nil {
		t.Fatalf("extraction failed: %v", err)
	}

	t.Logf("extracted %d chars: %s", len(text), text)
}

func TestExtractTextBoundedOnMassiveInput(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("<html><body>")
	for i := 0; i < 200000; i++ {
		sb.WriteString("<div><p>filler text here</p></div>")
	}
	sb.WriteString("</body></html>")
	raw := []byte(sb.String())

	start := time.Now()
	text, err := ExtractText(raw, 5*1024*1024)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("extraction failed: %v", err)
	}
	t.Logf("processed %d bytes in %v, extracted %d chars", len(raw), elapsed, len(text))
	if elapsed > 2*time.Second {
		t.Fatalf("extraction too slow for production: %v", elapsed)
	}
}
