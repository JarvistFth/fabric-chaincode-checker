package Context

import (
	"chaincode-checker/go-taint/lattice"
	"fmt"
	"golang.org/x/tools/go/ssa"
)

type ContextCallSuite struct {
	*ValueContext
	Node ssa.Instruction
	In   lattice.Lattice
	Out  lattice.Lattice
}

func (s *ContextCallSuite) Equal(c *ContextCallSuite) bool {
	eqCtx := c.GetValueContext().
}

func (s *ContextCallSuite) GetNode() ssa.Instruction {
	return s.Node
}

func (s *ContextCallSuite) GetValueContext() *ValueContext {
	return s.ValueContext
}

func (s ContextCallSuite) String() string {
	return fmt.Sprintf("context: %s ,\n node: %s ,\n in: %s ,\n , out: %s ,\n ",s.GetValueContext().String(),s.Node.String(),s.GetIn())
}