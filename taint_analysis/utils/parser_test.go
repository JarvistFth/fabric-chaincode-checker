package utils

import (
	"testing"
)

type F struct {
	f int
}

func TestParseSourceAndSinkFile(t *testing.T) {

	ptr := get(1)
	ptr.f = 1
}

func get(p int) *F{
	if p == 1{
		return nil
	}
	return &F{}
}