package context

import (
	"chaincode-checker/go-taint/lattice"
	"golang.org/x/tools/go/ssa"
)

type ValueContextIndent struct {
	In lattice.Lattice
	Function *ssa.Function
}

func NewValueCtxIndent(in lattice.Lattice, function *ssa.Function) *ValueContextIndent {
	ret := &ValueContextIndent{
		In:       in,
		Function: function,
	}
	return ret
}




func (v *ValueContextIndent) GetIn() lattice.Lattice {
	return v.In
}

func (v *ValueContextIndent) SetIn(l lattice.Lattice) {
	v.In = l

}

func (v *ValueContextIndent) GetFunction() *ssa.Function {
	return v.Function
}

func (v *ValueContextIndent) SetFunction(f *ssa.Function) {
	v.Function = f
}

func (v *ValueContextIndent) Equal(vi *ValueContextIndent) bool {
	ineq,_ := vi.GetIn().Equal(v.In)
	return ineq && v.Function == vi.GetFunction()
}
