package ast

import (
	"chaincode-checker/config"
	"testing"
)



func TestTestAst(t *testing.T) {
	FindRand(config.GoccPath)
}

func TestTryCFG(t *testing.T) {
	TryCFG(config.GoccPath)
}