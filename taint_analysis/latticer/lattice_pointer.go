package latticer

import (
	"chaincode-checker/taint_analysis/logger"
	"fmt"
	"github.com/pkg/errors"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
)

var log = logger.GetLogger("./debuglogs/test")

type LatticePointer struct {
	val *LatticeValue
	ptr *pointer.Pointer

}

func NewLatticePointer(key string, value ssa.Value, valToPtr map[ssa.Value]pointer.Pointer) *LatticePointer {
	var tag LatticeTag
	if _,cnst := value.(*ssa.Const); cnst{
		tag = Untainted
	}else{
		tag = Uninitialized
	}

	v := &LatticeValue{
		key:   key,
		value: value,
		tag:   tag,
		msg:   "",
	}


	if ptr,ok := valToPtr[value];ok{
		return &LatticePointer{
			val: v,
			ptr: &ptr,
		}
	}else{
		log.Warningf("can't find ptr for value:%s = %s",value.Name(),value.String())
		return &LatticePointer{
			val: v,
			ptr: nil,
		}
	}

}

func (p *LatticePointer) LeastUpperBound(l2 Lattice) error {
	err := p.val.LeastUpperBound(l2)
	if err != nil{
		return errors.Errorf("error least upper bound, %s,%s", p.String(),l2.String())
	}
	return nil
}

func (p *LatticePointer) GreatestLowerBound(l2 Lattice) error {
	err := p.val.GreatestLowerBound(l2)
	if err != nil{
		return errors.Errorf("error GreatestLowerBound, %s,%s", p.String(),l2.String())
	}
	return nil


}


func (p *LatticePointer) Less(l2 Lattice) (bool, error) {
	return p.val.Less(l2)
}

func (p *LatticePointer) Equal(l2 Lattice) (bool, error) {
	return p.val.Equal(l2)
}

func (p *LatticePointer) LessEqual(l2 Lattice) (bool, error) {
	return p.val.LessEqual(l2)
}

func (p *LatticePointer) Greater(l2 Lattice) (bool, error) {
	return p.val.Greater(l2)
}

func (p *LatticePointer) GreaterEqual(l2 Lattice) (bool, error) {
	return p.val.GreaterEqual(l2)
}

func (p *LatticePointer) Untaint() {
	p.val.Untaint()
}

func (p *LatticePointer) ResetTag() {
	p.val.ResetTag()
}

func (p *LatticePointer) DeepCopy() Lattice {



	return &LatticePointer{
		val: p.val,
		ptr: p.ptr,
	}
}

func (p *LatticePointer) String() string {
	if p.ptr != nil{
		return fmt.Sprintf("%s ptr: %s", p.val.String(), p.ptr.String())
	}else{
		return fmt.Sprintf("%s ptr: nil", p.val.String())
	}
}

func (p *LatticePointer) SetTag(tag LatticeTag){
	p.val.SetTag(tag)
}

func (p *LatticePointer) GetTag() LatticeTag {
	return p.val.GetTag()
}

func (p *LatticePointer) GetKey() string {
	return p.val.key
}

func (p *LatticePointer) GetPtr() *pointer.Pointer {
	return p.ptr
}

func (p *LatticePointer) SetPtr(ptr *pointer.Pointer) {
	p.ptr = ptr
}

func (p *LatticePointer) GetLatticeValue() Lattice {
	return p.val
}

func (p *LatticePointer) GetMsg() string {
	return p.val.msg
}

func (p *LatticePointer) SetMsg(msg string)  {
	p.val.msg = msg
}

//func (p *LatticePointer) GetSSAValMayAlias(v ssa.Value) []ssa.Value {
//	ret := make([]ssa.Value,0)
//
//	vptr := p.GetPtr(v)
//	ptrs := p.GetPtrs()
//
//	for v, ptr := range ptrs{
//		if ptr.MayAlias(vptr){
//			ret = append(ret,v)
//		}
//	}
//	return ret
//}
//
//func (p *LatticePointer) TransferFunction(node ssa.Instruction, ptr *pointer.Result) PlainFF {
//	//fmt.Printf("nodeptr: %s\n",node.String())
//	switch nType := node.(type) {
//	case *ssa.UnOp:
//		if nType.Op != token.MUL && nType.Op != token.ARROW {
//			l := p.GetLatticeValue().(*LatticeValue)
//			return l.TransferFunction(node, ptr)
//		}
//		//handling unop ptrs
//		return ptrUnOp(nType, p, ptr)
//	case *ssa.Store:
//		// *t1 = t0
//		// everything which mayalias the addres should set to the latticer value of val.
//		addr := nType.Addr
//		lupVal := p.GetTag(nType.Val)
//		//log.Warningf("ptr node store: %s, type.val: %s, tag: %s, addr: %s",node.String(),nType.Val.String(),lupVal.String(),addr.String())
//		if ptr != nil {
//			if ok, addrp := utils.IsPointerVal(addr); ok {
//				q := ptr.Queries[addrp]
//				qset := q.PointsTo()
//				labels := qset.Labels()
//				//log.Warningf("addrname:%s, valname:%s, qset: %s, len(labels):%d", addr.Name(), nType.Val.Name(),qset.String(), len(labels))
//				for _, l := range labels {
//					//log.Warningf("ptr store, label: %s, value: %s, valuetag:%s",l.String(), l.Value().Name(),lupVal.String())
//					p.GetLattice().SetTag(l.Value(), lupVal)
//					for ssav, ptr := range p.GetPtrs() {
//						if ptr.MayAlias(p.GetPtr(l.Value())) {
//							p.GetLattice().SetTag(ssav, lupVal)
//						}
//					}
//				}
//			}
//		}
//		//log.Warningf("ptr latticer:%s",p.GetLattice().String())
//		p.GetLattice().SetTag(addr, lupVal)
//	case *ssa.Call, *ssa.Defer, *ssa.Go:
//		ff := checkAndHandleSourcesAndsinks(node, p, true)
//		if ff == nil {
//			return returnID
//		} else {
//			return ff
//		}
//	}
//	l := p.GetLattice().(*LatticeValue)
//	return l.TransferFunction(node, ptr)
//}
//
//
//func ptrUnOp(e *ssa.UnOp, l *LatticePointer, ptr *pointer.Result) PlainFF {
//	value := e.X
//	switch e.X.(type){
//	case *ssa.Global:
//		log.Infof("ptrUnOp global value: %s",e.X.Name())
//		l.SetTag(Tainted)
//	default:
//
//	}
//
//	//isSource := isGlobalSource(e.X.Name())
//	//if isSource{
//	//	l.SetTag(e.X,Tainted)
//	//}
//	lupVal := l.GetTag(e.X)
//	if ptr != nil {
//		if ok, valr := utils.IsPointerVal(value); ok {
//			q := ptr.Queries[valr]
//			labels := q.PointsTo().Labels()
//			for _, la := range labels {
//
//				l.GetLattice().SetTag(la.Value(), lupVal)
//				for ssav, p := range l.GetPtrs() {
//					if p.MayAlias(l.GetPtr(la.Value())) {
//						l.GetLattice().SetTag(ssav, lupVal)
//					}
//				}
//			}
//		}
//
//		if ok, valr := utils.IsIndirectPtr(value); ok {
//			q := ptr.Queries[valr]
//			labels := q.PointsTo().Labels()
//			for _, la := range labels {
//
//				l.GetLattice().SetTag(la.Value(), lupVal)
//				for ssav, p := range l.GetPtrs() {
//					if p.MayAlias(l.GetPtr(la.Value())) {
//						l.GetLattice().SetTag(ssav, lupVal)
//					}
//				}
//			}
//		}
//	}
//	ret := returnLUP(lupVal)
//	//return returnLUP(ret)
//	return ret
//}

