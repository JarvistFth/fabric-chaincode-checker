package lattice

type LatticeTag int



const(
	Uninitialized LatticeTag = iota

	// Tainted represents a tainted abstract value.
	Tainted
	// Untainted represents an untainted abstract value.
	Untainted
	// Both represents the highest abstract value.
	Both
)

func (t LatticeTag) BottomElement() LatticeTag {
	return Uninitialized
}

func (t LatticeTag) TopElement() LatticeTag {
	return Both
}

func (t LatticeTag) LeastUpperBound(t1 LatticeTag) LatticeTag {
	return t | t1
}

func (t LatticeTag) GreatestUpperBound(t1 LatticeTag) LatticeTag  {
	return t & t1
}

func (t LatticeTag) Less(t1 LatticeTag) bool {
	if (t == Tainted && t1 == Untainted) || (t == Untainted && t1 == Tainted) {
		return false
	}
	return t < t1
}

func (t LatticeTag) Equal(t1 LatticeTag) bool {
	return t == t1
}

func (t LatticeTag) LessEqual(t1 LatticeTag) bool {
	return t.Less(t1) || t.Equal(t1)
}

func (t LatticeTag) Greater(t1 LatticeTag) bool {
	if (t == Tainted && t1 == Untainted) || (t == Untainted && t1 == Tainted) {
		return false
	}
	return t > t1
}

func (t LatticeTag) GreaterEqual(t1 LatticeTag) bool {
	return t.Equal(t1) || t.Greater(t1)
}

func (t LatticeTag) String() string {
	switch t {
	case Uninitialized:
		return "Uninitialized"
	case Untainted:
		return "Untainted"
	case Tainted:
		return "Tainted"
	case Both:
		return "Both"
	default:
		return "UnknownType"
	}
}

func (t LatticeTag) Error() string {
	panic("implement me")
}
