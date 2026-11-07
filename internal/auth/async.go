package auth

import "context"

// callWithContext runs fn in a new goroutine. The libraries used for SPF,
// DKIM, and DMARC do not accept a context, so a canceled context cannot stop
// the resolver. ok is false when ctx ends before fn returns. The goroutine
// is left running until fn returns.
func callWithContext[T any](ctx context.Context, fn func() T) (T, bool) {
	ch := make(chan T, 1)
	go func() {
		ch <- fn()
	}()

	// A context that is already done must win even if fn has finished and
	// the result is buffered. Otherwise select would choose at random.
	select {
	case <-ctx.Done():
		var zero T
		return zero, false
	default:
	}

	select {
	case <-ctx.Done():
		var zero T
		return zero, false
	case v := <-ch:
		return v, true
	}
}
