package core

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestContains(t *testing.T) {
	values := []string{"a", "b", "c"}

	assert.True(t, Contains("a", values))
	assert.False(t, Contains("d", values))
}

func TestAnyIsIn(t *testing.T) {
	values := []string{"a", "b", "c"}

	intersectingValues := []string{"g", "h", "i", "a"}
	missing := []string{"d", "e", "f"}

	assert.True(t, AnyIsIn(intersectingValues, values))
	assert.False(t, AnyIsIn(missing, values))
}
