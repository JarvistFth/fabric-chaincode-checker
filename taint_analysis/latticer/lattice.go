package latticer

type Lattices []Lattice

type Lattice interface {
	LeastUpperBound(l2 Lattice) error

	GreatestLowerBound(l2 Lattice) error

	Less(l2 Lattice) (bool,error)

	Equal(l2 Lattice) (bool, error)

	LessEqual(l2 Lattice) (bool,error)

	Greater(l2 Lattice) (bool,error)

	GreaterEqual(l2 Lattice) (bool,error)

	ResetTag()

	Untaint()

	DeepCopy() Lattice

	String() string

	SetTag(tag LatticeTag)

	GetTag() LatticeTag

	GetKey() string
}

