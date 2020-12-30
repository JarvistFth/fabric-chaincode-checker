package context

import (
	"chaincode-checker/go-taint/lattice"
	"fmt"
	"golang.org/x/tools/go/ssa"
)

type ContextCallSuite struct {
	*ValueContext
	node ssa.Instruction
	in   lattice.Lattice
	out  lattice.Lattice
}

func NewContextCallSuite(vc *ValueContext, node ssa.Instruction, in,out lattice.Lattice) *ContextCallSuite {
	ret := &ContextCallSuite{
		ValueContext: vc,
		node:         node,
		in:           in,
		out:          out,
	}
	return ret

}

func (s *ContextCallSuite) Equal(c *ContextCallSuite) bool {

	eqCtx := c.GetValueContext().Equal(c.GetValueContext())
	eqNode := s.node == c.node
	eqIn,_ := s.in.Equal(c.in)
	eqOut,_ := s.out.Equal(c.out)
	return eqCtx && eqNode && eqIn && eqOut
}

func (s *ContextCallSuite) GetNode() ssa.Instruction {
	return s.node
}

func (s *ContextCallSuite) GetValueContext() *ValueContext {
	return s.ValueContext
}

func (s *ContextCallSuite) String() string {
	return fmt.Sprintf("context: %s , node: %s , in: %s , out: %s",s.GetValueContext().String(),s.node.String(),s.GetIn().String(),s.GetOut().String())
}

func (s *ContextCallSuite) SetIn(l lattice.Lattice) {
	s.in,_ = s.in.LeastUpperBound(l)
}

func (s *ContextCallSuite) SetOut(l lattice.Lattice) {
	s.out,_ = s.GetOut().LeastUpperBound(l)
}

func (s *ContextCallSuite) GetOut() lattice.Lattice {
	return s.out
}

func (s *ContextCallSuite) GetIn() lattice.Lattice {
	return s.in
}
