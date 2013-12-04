package main

import (
	"testing"
)

func cleanupHelper(t *testing.T, input, expected string) {
	var iv []byte = []byte(input)
	var out string = cleanupQuery(iv)
	if out != expected {
		t.Errorf("For query %s\n    Got %s\n    Expected %s", input, out, expected)
	}
}

func TestSimple(t *testing.T) {
	cleanupHelper(t, "select * from table where col=1",
		"select * from table where col=?")

	// Should these be ?? or ?
	cleanupHelper(t, "select * from table where col=\"hello\"", "select * from table where col=?")
	cleanupHelper(t, "select * from table where col='hello'", "select * from table where col=?")

	cleanupHelper(t, "select * from table where col='\\''", "select * from table where col=?")
}

func TestMultipleIn(t *testing.T) {
	cleanupHelper(t, "select * from table where x in (1, 2, 'foo')",
		"select * from table where x in (?)")
}

func TestWhitespace(t *testing.T) {
	cleanupHelper(t, "select *     from      table", "select * from table")
	cleanupHelper(t, "select *\nfrom\n\n\n\r\ntable", "select * from table")
}

func TestFailing(t *testing.T) {
	cleanupHelper(t, "select * from s2compiled", "select * from s2compiled")

	// Should these be ??, as above
	cleanupHelper(t, "select * from table where col=\"'\"", "select * from table where col=?")
	cleanupHelper(t, "select * from table where col='\"'", "select * from table where col=?")
}
