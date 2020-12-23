package lattice

import (
	"fmt"
	"github.com/pkg/errors"
	"golang.org/x/tools/go/ssa"
	"reflect"
	"strings"
)

type LatticeValue map[ssa.Value]LatticeTag

func (v LatticeValue) Empty() bool {
	return len(v) <= 0
}

func NewLattice(len int) LatticeValue {
	return make(map[ssa.Value]LatticeTag)
}

func (v LatticeValue) GetTag(key ssa.Value) LatticeTag {
	val := v[key]
	if val == Uninitialized{
		if _,cnst := key.(*ssa.Const); cnst{
			v[key] = Untainted
			val = Untainted
		}else{
			v[key] = Uninitialized
		}
	}
	return val
}

func (v LatticeValue) SetTag(key ssa.Value, tag LatticeTag) error{
	if key != nil{
		v[key] = tag
		return nil
	}
	return errors.Errorf("Set tag, key not exits")

}


func (v LatticeValue) LeastUpperBound(l2 Lattice) (Lattice, error) {
	l2val,err := getTaintVal(l2)
	if err != nil{
		return nil,errors.Errorf(err.Error())
	}

	var added bool
	var smallerL, biggerL LatticeValue
	if len(v) > len(l2val) {
		smallerL = l2val.DeepCopy().(LatticeValue)
		biggerL = v.DeepCopy().(LatticeValue)
	}else {
		smallerL = v.DeepCopy().(LatticeValue)
		biggerL = l2val.DeepCopy().(LatticeValue)
	}

	RangeL0:
		for ssaVal0, val0 := range biggerL{
			added = false
			if ssaVal0 == nil{
				continue RangeL0
			}

			RangeLI:
				for ssaValI, valI := range smallerL{
					if ssaValI == nil{
						continue RangeLI
					}
					// found a match between two ssa values -> build the lup of them
					if ssaVal0 == ssaValI{
						lUpperBound := val0.LeastUpperBound(valI)

						lUpperBoundTaint := lUpperBound

						biggerL[ssaVal0] = lUpperBoundTaint
						added = true
						delete(smallerL,ssaValI)
						continue RangeL0
					}
				}

				if !added{
					biggerL[ssaVal0] = val0
				}
		}

		for ssaValI, valI := range smallerL{
			biggerL[ssaValI] = valI
		}

		return biggerL,nil

}

func (v LatticeValue) GreatestLowerBound(l2 Lattice) (Lattice, error) {
	tempMap := NewLattice(len(v))

	for ssavalThis, tagThis := range v{
		tempMap[ssavalThis] = tagThis
	}

	l2Taint,err := getTaintVal(l2)

	if err != nil{
		errors.Wrap(err,"faled get Taint val")
	}

	var added bool

	for ssavalL2, valL2 := range l2Taint{
		added = false

		for ssavalL1, valL1 := range tempMap {
			if ssavalL1.Name() == ssavalL2.Name(){
				var glbTag LatticeTag

				glbTag = valL1.GreatestUpperBound(valL2)

				tempMap[ssavalL1] = glbTag
				added = true
			}
		}

		if !added{
			tempMap[ssavalL2] = valL2
		}
	}

	ret := make(LatticeValue)

	for k,v := range tempMap{
		ret[k] = v
	}

	return ret,nil



}

func (v LatticeValue) LeastElement() (Lattice, error) {
	ret := make(LatticeValue)

	for ssaval := range v{
		ret[ssaval] = Uninitialized
	}

	return ret,nil
}

func (v LatticeValue) Less(l2 Lattice) (bool, error) {
	l2Tag,err := getTaintVal(l2)
	if err != nil{
		return false,errors.Wrap(err,"failed less get taint lattice")
	}

	for ssavalL1, tagL1 := range v{
		visited := false

		for ssavalL2, tagL2 := range l2Tag{


			if ssavalL2.Name() == ssavalL1.Name(){
				less:= tagL1.Less(tagL2)

				if !less{
					return false,nil
				}
				visited = true
			}
		}

		if !visited && tagL1 != Uninitialized{
			return false, nil
		}
	}

	return true,nil
}

func (v LatticeValue) Equal(l2 Lattice) (bool, error) {
	l2Tag,err := getTaintVal(l2)
	if err != nil{
		return false,errors.Wrap(err,"failed less get taint lattice")
	}

	for ssavalL1, tagL1 := range v{
		visited := false

		for ssavalL2, tagL2 := range l2Tag{

			if ssavalL2 == ssavalL1{
				eq:= tagL1.Equal(tagL2)

				if !eq{
					return false,nil
				}
				visited = true
			}
		}

		if !visited && tagL1 != Uninitialized{
			return false, nil
		}
	}

	for ssavalL2,tagL2 := range l2Tag{
		visited := false
		for ssavalL1,tagL1 := range v{
			if ssavalL1 == ssavalL2{
				eq := tagL2.Equal(tagL1)
				if !eq{
					return false,nil
				}
				visited = true
			}
		}

		if !visited && tagL2 != Uninitialized{
			return false,nil
		}
	}

	return true,nil
}

func (v LatticeValue) LessEqual(l2 Lattice) (bool, error) {
	eq,err := v.Equal(l2)
	if err != nil{
		return false,errors.Wrap(err,"")
	}
	if eq{
		return true,nil
	}
	less,err := v.Less(l2)

	if err != nil{
		return false,errors.Wrap(err,"")
	}

	return less,nil



}

func (v LatticeValue) Greater(l2 Lattice) (bool, error) {
	l2val,err := getTaintVal(l2)
	if err != nil{
		return false,errors.Wrap(err,"")
	}

	for ssavalL1,valL1 := range v{

		visited := false

		for ssavalL2,valL2 := range l2val{


			if ssavalL2.Name() == ssavalL1.Name(){
				gt := valL1.Greater(valL2)
				if !gt{
					return false,nil
				}
				visited = true
			}
		}

		if !visited && valL1 != Uninitialized{
			return false,nil
		}
	}

	return true,nil
}

func (v LatticeValue) GreaterEqual(l2 Lattice) (bool, error) {
	gt,err := v.Greater(l2)
	if err != nil{
		return false,errors.Wrap(err,"")
	}

	if gt{
		return true,nil
	}

	eq,err := v.Equal(l2)
	if err != nil{
		return false, errors.Wrap(err,"")
	}

	if eq{
		return true,nil
	}

	return false,nil
}

func (v LatticeValue) BottomLattice() Lattice {
	ret := make(LatticeValue)

	for k := range v{
		ret[k] = Uninitialized
	}

	return ret
}

func (v LatticeValue) DeepCopy() Lattice {
	ret := make(LatticeValue)

	for k,val := range v{
		ret[k] = val
	}
	return ret
}

func (v LatticeValue) String() string {

	var s string
	for ssaval,tag := range v{
		if ssaval == nil{
			s += fmt.Sprintf("nil: %s | ", tag.String())
		}else{
			if strings.Contains(ssaval.Name(),"nil"){
				t := strings.Replace(ssaval.Name(),"nil","",-1)
				s += fmt.Sprintf("nil + %s : %s | ",t,tag.String())
			}else{
				s += fmt.Sprintf("%s, : %s | ",ssaval.Name(),tag.String())
			}
		}
	}
	return s
}

func getTaintVal(l Lattice) (LatticeValue,error) {
	val, ok := l.(LatticeValue)
	if ok{
		return val,nil
	}else{
		ptr, ok := l.(*LatticePointer)
		if ok{
			lat := ptr.GetLattice()
			latticeval, ok := lat.(LatticeValue)
			if ok{
				return latticeval,nil
			}
		}
		return nil,errors.Errorf("get taint value:, get type: %s",reflect.TypeOf(l).String())
	}
}
