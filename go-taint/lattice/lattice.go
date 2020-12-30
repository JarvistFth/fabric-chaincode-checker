package lattice

import (
	"golang.org/x/tools/go/ssa"
)

type LatticeType int

const(
	Value LatticeType = iota

	Pointer

)

type Lattice interface {
	LeastUpperBound(l2 Lattice) (Lattice,error)

	GreatestLowerBound(l2 Lattice) (Lattice,error)

	LeastElement() (Lattice,error)

	Less(l2 Lattice) (bool,error)

	Equal(l2 Lattice) (bool, error)

	LessEqual(l2 Lattice) (bool,error)

	Greater(l2 Lattice) (bool,error)

	GreaterEqual(l2 Lattice) (bool,error)

	BottomLattice() Lattice

	DeepCopy() Lattice

	String() string

	SetTag(key ssa.Value, tag LatticeTag)error

	GetTag(key ssa.Value) LatticeTag


}








