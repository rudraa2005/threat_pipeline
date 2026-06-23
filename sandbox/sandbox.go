package sandbox

import (
	"context"
	"fmt"
	"threat_pipeline/detection"
	"time"
)

type Result struct {
	Matches []detection.RuleMatch
	Risk    detection.Risk
	Err     error
	Timeout bool
}

func Sandbox(ctx context.Context, doc string, engine *detection.RuleEngine) Result {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	ch := make(chan Result, 1)
	go func() {

		defer func() {
			if r := recover(); r != nil {
				ch <- Result{
					Err: fmt.Errorf("analysis panic %v", r),
				}
			}
		}()
		matches := engine.Evaluate(doc)
		risk := detection.Scorer(matches)

		ch <- Result{
			Matches: matches,
			Risk:    risk,
		}
	}()

	select {
	case result := <-ch:
		return result

	case <-ctx.Done():
		return Result{
			Timeout: true,
			Err:     ctx.Err(),
		}
	}
}
