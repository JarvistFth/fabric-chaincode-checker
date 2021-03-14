package context

import (
	"chaincode-checker/taint_analysis/latticer"
	"chaincode-checker/taint_analysis/config"
	"chaincode-checker/taint_analysis/utils"
	"golang.org/x/tools/go/ssa"
	"sort"
)


type LatticeMap map[string]latticer.Lattice
var LatticeTable LatticeMap



func (v LatticeMap) GetLattice(value ssa.Value) latticer.Lattice {
	key := utils.GenKeyFromSSAValue(value)
	if ret,ok := v[key];ok{
		return ret
	}else{
		if config.Config.WithPtr{
			v[key] = latticer.NewLatticePointer(key,value, config.WorkingProject.ValToPtrs)
		}else{
			v[key] = latticer.NewLatticeValue(key,value)
		}
	}

	return v[key]
}

func (v LatticeMap) Len() int {
	return len(v)
}

func (v LatticeMap) GetTag(key string) (latticer.LatticeTag,bool){
	if lat,ok := v[key];ok {
		return lat.GetTag(),ok
	}else{
		return latticer.Uninitialized,false
	}
}

func (v LatticeMap) Add(key string, lattice latticer.Lattice)  {
	v[key] = lattice
}

func (v LatticeMap) Contain(key string) (latticer.Lattice, bool) {
	ret,ok := v[key]
	return ret,ok
}

func (v LatticeMap) String() string {
	var ret string

	keys := make([]string, 0)

	for k := range v{
		keys = append(keys,k)
	}

	sort.Strings(keys)

	for _,k := range keys{
		ret += v[k].String() + "\n"
	}

	return ret

}

