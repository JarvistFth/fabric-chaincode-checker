package context

import (
	"chaincode-checker/go-taint/lattice"
	"fmt"
	"golang.org/x/tools/go/ssa"
)


var idCounter = 0

type ValueContext struct {
	//ValueIdentInterface

	RetValueLattice lattice.Lattice

	Id int
	Params []ssa.Value

	ValueIndent *ValueContextIndent
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

func NewValueContext(vi *ValueContextIndent, id int, exitval lattice.Lattice) *ValueContext {
	ret := &ValueContext{
		RetValueLattice: exitval,
		Id:              id,
		ValueIndent:     vi,
	}
	return ret
}

func (v *ValueContext) GetMethod() *ssa.Function {
	return v.ValueIndent.GetFunction()
}

func (v *ValueContext) GetEntryValue() lattice.Lattice {
	return v.ValueIndent.GetIn()
}

func (v *ValueContext) GetExitValue() lattice.Lattice {
	return v.RetValueLattice
}

func (v *ValueContext) NewEntryValue(entry lattice.Lattice) {
	l,_ := v.ValueIndent.GetIn().LeastUpperBound(entry)
	v.ValueIndent.SetIn(l)
}

func (v *ValueContext) NewExitValue(exit lattice.Lattice) {
	v.RetValueLattice,_ = v.RetValueLattice.LeastUpperBound(exit)
}

func (v *ValueContext) String() string {
	return fmt.Sprintf("[%d], Method:%s, EntryValue:%s, RetValueLattice:%s",v.Id, v.ValueIndent.GetFunction().String(), v.ValueIndent.GetIn().String(),v.RetValueLattice.String())
}

func (v *ValueContext) SameId(v2 *ValueContext) bool {
	return v.Id == v2.Id
}

func (v *ValueContext) Equal(v2 *ValueContext) bool {
	eqMethod := v.GetMethod() == v2.GetMethod()
	eqLattice,err := v.GetEntryValue().Equal(v2.GetEntryValue())
	if err != nil{
		return false
	}
	eqId := v.SameId(v2)

	return eqId && eqLattice && eqMethod
}

func (v *ValueContext) IsEntryEqual(v2 *ValueContext, params []ssa.Value) bool {

	if len(v.Params) != len(v2.Params){
		return false
	}

	if v.GetMethod() != v2.GetMethod(){
		return false
	}

	if v2.Params == nil || len(params) != len(v2.Params){
		return false
	}

	if len(params) > 0{
		for i,val := range params{
			vtaint1 := v.GetEntryValue().GetTag(val)
			vtaint2 := v.GetEntryValue().GetTag(v2.Params[i])
			if vtaint1 != vtaint2{
				return false
			}
		}
	}
	return true
}

func (v *ValueContext) SetEntryValue(entry lattice.Lattice) {
	v.ValueIndent.SetIn(entry)
}

