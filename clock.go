package xmldsig

import (
	"time"
)

// Clock represents anything capable of returning the current time stamp.
type Clock interface {
	// Now returns the current local time. See time package.
	Now() time.Time
}

// realClock is the default implementation of the Clock interface that returns
// the real current local time.
type realClock struct{}

// Now returns the real current local time.
func (rc *realClock) Now() time.Time { return time.Now() }

// fixedClock is an implementation of Clock that returns a fixed time.
type fixedClock struct {
	t time.Time
}

func (fc *fixedClock) Now() time.Time { return fc.t }
