package latticer

import (
	"chaincode-checker/taint_analysis/config"
	"chaincode-checker/taint_analysis/logger"
	"chaincode-checker/taint_analysis/utils"
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

func NewLatticePointer(value ssa.Value, valToPtr map[ssa.Value]pointer.Pointer) *LatticePointer {
	k := utils.GenKeyFromSSAValue(value)
	var tag LatticeTag
	if _,cnst := value.(*ssa.Const); cnst{
		tag = Untainted
	}else{
		tag = Uninitialized
	}

	v := &LatticeValue{
		key:   k,
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

func GetInLatticesFromParams(function *ssa.Function, isClosure bool) Lattices{

	var args []ssa.Value
	var ret Lattices
	if isClosure{
		fs := function.FreeVars
		args = make([]ssa.Value,len(fs))
		ret = make(Lattices,len(fs))
		for i,f := range args{
			args[i] = f
			lat:= NewLatticePointer(f,config.WorkingProject.ValToPtrs)
			ret = append(ret,lat)
		}
	}else{
		ps := function.Params
		args = make([]ssa.Value,len(ps))
		for i,p := range ps{
			args[i] = p
			lat:= NewLatticePointer(p,config.WorkingProject.ValToPtrs)
			ret = append(ret,lat)
		}
	}
	return ret


}
