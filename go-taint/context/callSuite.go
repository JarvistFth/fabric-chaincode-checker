package context

import (
	"chaincode-checker/go-taint/lattice"
	"fmt"
	"golang.org/x/tools/go/ssa"
)

type InstructionContext struct {
	*ValueContext
	node ssa.Instruction
	in   lattice.Lattice
	out  lattice.Lattice
}

func NewContextCallSuite(vc *ValueContext, node ssa.Instruction, in,out lattice.Lattice) *InstructionContext {
	ret := &InstructionContext{
		ValueContext: vc,
		node:         node,
		in:           in,
		out:          out,
	}
	return ret

}

func (s *InstructionContext) Equal(c *InstructionContext) bool {

	eqCtx := c.GetValueContext().Equal(c.GetValueContext())
	eqNode := s.node == c.node
	eqIn,_ := s.in.Equal(c.in)
	eqOut,_ := s.out.Equal(c.out)
	return eqCtx && eqNode && eqIn && eqOut
}

func (s *InstructionContext) GetNode() ssa.Instruction {
	return s.node
}

func (s *InstructionContext) GetValueContext() *ValueContext {
	return s.ValueContext
}

func (s *InstructionContext) String() string {
	return fmt.Sprintf("context: %s, name :%s\n Node: %s,\n In: %s,\n Out: %s", s.GetValueContext().String(),s.node.String(),s.GetIn().String(),s.GetOut().String())
}

func (s *InstructionContext) SetIn(l lattice.Lattice) {
	s.in,_ = s.in.LeastUpperBound(l)
}

func (s *InstructionContext) SetOut(l lattice.Lattice) {
	s.out,_ = s.GetOut().LeastUpperBound(l)
}

func (s *InstructionContext) GetOut() lattice.Lattice {
	return s.out
}

func (s *InstructionContext) GetIn() lattice.Lattice {
	return s.in
}
