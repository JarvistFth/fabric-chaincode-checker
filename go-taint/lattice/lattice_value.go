package lattice

import (
	"fmt"
	"github.com/pkg/errors"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
	"reflect"
	"strings"
)

type LatticeValue struct {
	key string
	value ssa.Value
	tag LatticeTag
	msg string
}



//type LatticeValue map[ssa.Value]LatticeTag

//func (v *LatticeValue) Empty() bool {
//	return len(v) <= 0
//}

func NewLatticeValue(key string, value ssa.Value) *LatticeValue {
	var tag LatticeTag
	if _,cnst := value.(*ssa.Const); cnst{
		tag = Untainted
	}else{
		tag = Uninitialized
	}
	return &LatticeValue{
		key:   key,
		value: value,
		tag:   tag,
		msg:   "",
	}
}

func (v *LatticeValue) GetTag() LatticeTag {
	return v.tag
}

func (v *LatticeValue) SetTag(tag LatticeTag){
	v.tag = tag

}


func (v *LatticeValue) LeastUpperBound(l2 Lattice) error {
	l2taint,err := getTaintVal(l2)
	if err != nil{
		errors.Wrap(err,"failed get taint val")
	}
	v.tag = v.tag.LeastUpperBound(l2taint.tag)
	return nil
}

func (v *LatticeValue) GreatestLowerBound(l2 Lattice)  error {


	l2Taint,err := getTaintVal(l2)

	if err != nil{
		errors.Wrap(err,"failed get Taint val")
	}

	v.tag = v.tag.GreatestLowerBound(l2Taint.tag)
	return nil



}


func (v *LatticeValue) Less(l2 Lattice) (bool, error) {
	l2val,err := getTaintVal(l2)
	if err != nil{
		return false,errors.Wrap(err,"failed less get taint lattice")
	}

	if v.tag.Less(l2val.tag){
		return true,nil
	}

	return false,nil
}

func (v *LatticeValue) Equal(l2 Lattice) (bool, error) {
	l2val,err := getTaintVal(l2)
	if err != nil{
		return false,errors.Wrap(err,"failed less get taint lattice")
	}
	return v.tag.Equal(l2val.tag),nil

}

func (v *LatticeValue) LessEqual(l2 Lattice) (bool, error) {
	l2val,err := getTaintVal(l2)
	if err != nil{
		return false,errors.Wrap(err,"failed get taint lattice value")
	}
	return v.tag.LessEqual(l2val.tag),nil



}

func (v *LatticeValue) Greater(l2 Lattice) (bool, error) {
	l2val,err := getTaintVal(l2)
	if err != nil{
		return false,errors.Wrap(err,"")
	}

	return v.tag.Greater(l2val.tag),nil
}

func (v *LatticeValue) GreaterEqual(l2 Lattice) (bool, error) {
	l2val,err := getTaintVal(l2)
	if err != nil{
		return false,errors.Wrap(err,"failed to get taint val at lattice value gteq")
	}

	return v.tag.GreaterEqual(l2val.tag),nil
}

func (v *LatticeValue) ResetTag() {
	v.tag = Uninitialized
}

func (v *LatticeValue) DeepCopy() Lattice {
	//ret := make(LatticeValue)
	//
	//for k,val := range v {
	//	ret[k] = val
	//}
	//return ret

	return &LatticeValue{
		key:   v.key,
		value: v.value,
		tag:   v.tag,
		msg:   v.msg,
	}

}

func (v *LatticeValue) String() string {
	return fmt.Sprintf("lattice value name:%s, operation:%s = %s\ntag:%s, msg:%s",v.key,v.value.Name(), v.value.Name(),v.value.String(),v.msg)
}

func getTaintVal(l Lattice) (*LatticeValue,error) {
	val, ok := l.(*LatticeValue)
	if ok{
		return val,nil
	}else{
		ptr, ok := l.(*LatticePointer)
		if ok{
			lat := ptr.GetLattice()
			latticeval, ok := lat.(*LatticeValue)
			if ok{
				return latticeval,nil
			}
		}
		return nil,errors.Errorf("get taint value:, get type: %s",reflect.TypeOf(l).String())
	}
}

