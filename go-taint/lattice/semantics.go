package lattice

import (
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
)

//Semanticer is an interface for a transfer function
//A transfer function describes the change in a Lattice caused by an expression.
//in our implementation, an expression is represented by a ssautils.Instruction.
type SemanticeInterface interface {
	// TransferFunction returns a PlainFF which describes the change of a lattice.Valuer caused by node
	TransferFunction(node ssa.Instruction, pointers *pointer.Result) PlainFF
}

// PlainFF describes a plain flow function without any connection to an instruction.
type PlainFF func(tag LatticeTag) (LatticeTag,error)
