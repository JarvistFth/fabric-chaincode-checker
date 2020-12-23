package Context

import (
	"chaincode-checker/go-taint/lattice"
	"fmt"
	"golang.org/x/tools/go/ssa"
)


var idCounter = 0

type ValueContext struct {
	//ValueIdentInterface

	ExitValue lattice.Lattice

	Id int
	Params []ssa.Value
}

//type ValueIdentInterface interface {
//	// GetIn returns the entry lattice of a value context
//	GetIn() lattice.Lattice
//
//	// SetIn updates the entry lattice of a value context with l
//	SetIn(l lattice.Lattice)
//
//	GetFunction() *ssa.Function
//
//	// SetFunction sets the function of a value context to f
//	SetFunction(f *ssa.Function)
//
//	// Equal returns true if the function and the entry lattice of two value contextes are equal
//	Equal(v ValueIdentInterface) bool
//}


type ValueContextIndent struct {
	In lattice.Lattice
	Function *ssa.Function
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

func (v *ValueContextIndent) Equal(vi ValueContextIndent) bool {
	ineq,_ := vi.GetIn().Equal(v.In)
	return ineq && v.Function == vi.GetFunction()
}



func (v *ValueContext) String() string {
	return fmt.Sprintf("[%d], Method:%s, EntryValue:%s, ExitValue:%s",v.Id, v,v.ExitValue.String())
}


