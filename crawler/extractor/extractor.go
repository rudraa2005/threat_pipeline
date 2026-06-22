package extractor

import (
	"strings"

	"golang.org/x/net/html"
)

var skipTags = map[string]bool{
	"script":   true,
	"style":    true,
	"noscript": true,
	"iframe":   true,
	"svg":      true,
}

func ExtractText(rawHTML []byte, maxBytes int) (string, error) {
	if len(rawHTML) > maxBytes {
		rawHTML = rawHTML[:maxBytes]
	}
	doc, err := html.Parse(strings.NewReader(string(rawHTML)))
	if err != nil {
		return "", err
	}

	var sb strings.Builder

	walk(doc, &sb)

	return cleanWhiteSpace(sb.String()), nil
}

func walk(n *html.Node, sb *strings.Builder) {
	if n.Type == html.ElementNode && skipTags[n.Data] {
		return
	}

	if n.Type == html.TextNode {
		text := strings.TrimSpace(n.Data)
		if text != "" {
			sb.WriteString(text)
			sb.WriteString(" ")
		}
	}

	for c := n.FirstChild; c != nil; c = c.NextSibling {
		walk(c, sb)
	}
}

func cleanWhiteSpace(s string) string {
	fields := strings.Fields(s)
	return strings.Join(fields, " ")
}
