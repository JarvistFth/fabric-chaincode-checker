package lattice

import (
	"chaincode-checker/go-taint/utils"
	"fmt"
	"github.com/pkg/errors"
	"go/token"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
)

type LatticePointer struct {
	Vals LatticeValue
	Ptrs map[ssa.Value]pointer.Pointer
}

func NewLatticePointer(len int, m map[ssa.Value]pointer.Pointer) *LatticePointer {
	return &LatticePointer{
		Vals: make(map[ssa.Value]LatticeTag, len),
		Ptrs: m,
	}
}

func (p *LatticePointer) LeastUpperBound(l2 Lattice) (Lattice, error) {
	lat,err := p.Vals.LeastUpperBound(l2)
	latTainted,ok := lat.(LatticeValue)
	if !ok || err != nil{
		return nil,errors.Errorf("error least upper bound, %s,%s",p.String(),l2.String())
	}
	ptrs:=p.GetPtrs()



	return &LatticePointer{
		Vals: latTainted,
		Ptrs:         ptrs,
	},nil

}

func (p *LatticePointer) GreatestLowerBound(l2 Lattice) (Lattice, error) {
	lat,err := p.Vals.GreatestLowerBound(l2)
	lattainted,ok := lat.(LatticeValue)
	if !ok || err != nil{
		return nil,errors.Errorf("err greatest lowerbound, %s,%s",p.String(),l2.String())
	}

	ptrs := p.GetPtrs()
	return &LatticePointer{
		Vals: lattainted,
		Ptrs:         ptrs,
	},nil


}

func (p *LatticePointer) LeastElement() (Lattice, error) {
	lat,err := p.Vals.LeastElement()
	lattainted,ok := lat.(*LatticeValue)
	if !ok || err != nil{
		return nil,errors.Errorf("err greatest lowerbound, %s",p.String())
	}

	ptrs := p.GetPtrs()
	return &LatticePointer{
		Vals: *lattainted,
		Ptrs:         ptrs,
	},nil
}

func (p *LatticePointer) Less(l2 Lattice) (bool, error) {
	return p.Vals.Less(l2)
}

func (p *LatticePointer) Equal(l2 Lattice) (bool, error) {
	return p.Vals.Equal(l2)
}

func (p *LatticePointer) LessEqual(l2 Lattice) (bool, error) {
	return p.Vals.LessEqual(l2)
}

func (p *LatticePointer) Greater(l2 Lattice) (bool, error) {
	return p.Vals.Greater(l2)
}

func (p *LatticePointer) GreaterEqual(l2 Lattice) (bool, error) {
	return p.Vals.GreaterEqual(l2)
}

func (p *LatticePointer) BottomLattice() Lattice {
	lat := p.Vals.BottomLattice()
	lattainted := lat.(LatticeValue)
	ptrs := p.GetPtrs()
	return &LatticePointer{
		Vals: lattainted,
		Ptrs: ptrs,
	}
}

func (p *LatticePointer) DeepCopy() Lattice {
	q := make(map[ssa.Value]pointer.Pointer)

	for i,ptr := range p.Ptrs{
		q[i] = ptr
	}

	lat := p.GetLattice().(LatticeValue)
	return &LatticePointer{
		Vals: lat,
		Ptrs: q,
	}
}

func (p *LatticePointer) String() string {
	return fmt.Sprintf("LatticePointer: %s",p.Vals.String())
}

func (p *LatticePointer) GetPtrs() map[ssa.Value]pointer.Pointer {
	return p.Ptrs
}

func (p *LatticePointer) SetPtrs(m map[ssa.Value]pointer.Pointer)  {
	p.Ptrs = m
}

func (p *LatticePointer) SetTag(key ssa.Value, tag LatticeTag) error{
	return p.Vals.SetTag(key,tag)
}

func (p *LatticePointer) GetTag(key ssa.Value) LatticeTag {
	return p.Vals.GetTag(key)
}

func (p *LatticePointer) GetPtr(key ssa.Value) pointer.Pointer {
	return p.Ptrs[key]
}

func (p *LatticePointer) SetPtr(key ssa.Value, ptr pointer.Pointer) {
	p.Ptrs[key] = ptr
}

func (p *LatticePointer) GetLattice() Lattice {
	if p == nil || p.Vals == nil{
		m := make(map[ssa.Value]pointer.Pointer)
		NewLatticePointer(0,m)
	}
	return p.Vals
}

func (p *LatticePointer) GetSSAValMayAlias(v ssa.Value) []ssa.Value {
	ret := make([]ssa.Value,0)

	vptr := p.GetPtr(v)
	ptrs := p.GetPtrs()

	for v, ptr := range ptrs{
		if ptr.MayAlias(vptr){
			ret = append(ret,v)
		}
	}
	return ret
}

func (l1 *LatticePointer) TransferFunction(node ssa.Instruction, ptr *pointer.Result) PlainFF {
	switch nType := node.(type) {
	case *ssa.UnOp:
		if nType.Op != token.MUL && nType.Op != token.ARROW {
			l := l1.GetLattice().(LatticeValue)

			return l.TransferFunction(node, ptr)
		}
		//handling unop ptrs
		return ptrUnOp(nType, l1, ptr)
	case *ssa.Store:
		// *t1 = t0
		// everything which mayalias the addres should set to the lattice value of val.
		addr := nType.Addr
		lupVal := l1.GetTag(nType.Val)
		if ptr != nil {
			if ok, addrp := utils.IsPointerVal(addr); ok {
				q := ptr.Queries[addrp]
				qset := q.PointsTo()
				lbaels := qset.Labels()
				for _, l := range lbaels {
					l1.GetLattice().SetTag(l.Value(), lupVal)
					for ssav, p := range l1.GetPtrs() {
						if p.MayAlias(l1.GetPtr(l.Value())) {
							l1.GetLattice().SetTag(ssav, lupVal)
						}
					}
				}
			}
		}
		l1.GetLattice().SetTag(addr, lupVal)
	case *ssa.Call, *ssa.Defer, *ssa.Go:
		ff := checkAndHandleSourcesAndsinks(node, l1, true)
		if ff == nil {
			return returnID
		} else {
			return ff
		}
	}
	l := l1.GetLattice().(LatticeValue)
	return l.TransferFunction(node, ptr)
}


func ptrUnOp(e *ssa.UnOp, l *LatticePointer, ptr *pointer.Result) PlainFF {
	value := e.X
	lupVal := l.GetTag(e.X)

	if ptr != nil {
		if ok, valr := utils.IsPointerVal(value); ok {
			q := ptr.Queries[valr]
			labels := q.PointsTo().Labels()
			for _, la := range labels {

				l.GetLattice().SetTag(la.Value(), lupVal)
				for ssav, p := range l.GetPtrs() {
					if p.MayAlias(l.GetPtr(la.Value())) {
						l.GetLattice().SetTag(ssav, lupVal)
					}
				}
			}
		}

		if ok, valr := utils.IsIndirectPtr(value); ok {
			q := ptr.Queries[valr]
			labels := q.PointsTo().Labels()
			for _, la := range labels {

				l.GetLattice().SetTag(la.Value(), lupVal)
				for ssav, p := range l.GetPtrs() {
					if p.MayAlias(l.GetPtr(la.Value())) {
						l.GetLattice().SetTag(ssav, lupVal)
					}
				}
			}
		}
	}
	return returnLUP(lupVal)
}

