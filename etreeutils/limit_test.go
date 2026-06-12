package etreeutils

import "testing"

// TestCheckLimitZeroValueContext: a zero-value NSContext (EmptyNSContext is
// exported and the zero value is constructible by any caller) has no limit
// pointer — CheckLimit must treat it as unlimited, not dereference nil.
func TestCheckLimitZeroValueContext(t *testing.T) {
	if err := EmptyNSContext.CheckLimit(); err != nil {
		t.Fatalf("EmptyNSContext.CheckLimit() = %v, want nil", err)
	}

	var zero NSContext
	for i := 0; i < 5000; i++ { // would exhaust any accidental default budget
		if err := zero.CheckLimit(); err != nil {
			t.Fatalf("zero-value NSContext.CheckLimit() = %v on call %d, want nil", err, i)
		}
	}
}

// TestCheckLimitBudget pins the budgeted behaviour CheckLimit has always had.
func TestCheckLimitBudget(t *testing.T) {
	ctx := NewNSContextWithLimit(2)
	if err := ctx.CheckLimit(); err != nil {
		t.Fatal(err)
	}
	if err := ctx.CheckLimit(); err != nil {
		t.Fatal(err)
	}
	if err := ctx.CheckLimit(); err != ErrTraversalLimit {
		t.Fatalf("third call = %v, want ErrTraversalLimit", err)
	}
}
