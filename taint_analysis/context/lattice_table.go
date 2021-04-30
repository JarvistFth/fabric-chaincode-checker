package context

import (
	"chaincode-checker/taint_analysis/latticer"
	"chaincode-checker/taint_analysis/config"
	"chaincode-checker/taint_analysis/utils"
	"golang.org/x/tools/go/ssa"
	"sort"
)


type LatticeMap map[string]latticer.Lattice
type stringslice []string
var LatticeTable LatticeMap



func (v LatticeMap) GetLattice(value ssa.Value) latticer.Lattice {
	key := utils.GenKeyFromSSAValue(value)
	if ret,ok := v[key];ok{
		return ret
	}else{
		if config.Config.WithPtr{
			v[key] = latticer.NewLatticePointer(value, config.ValToPtrs)
		}else{
			v[key] = latticer.NewLatticeValue(value)
		}
	}

	return v[key]
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

func (v LatticeMap) Len() int {
	return len(v)
}

func (v LatticeMap) Swap(i, j string) {
	v[i],v[j] = v[j],v[i]
}

func (v LatticeMap) Less(s1, s2 string) bool {
	if len(s1) != len(s2){
		return len(s1) < len(s2)
	}else{
		diff := 0
		for i := 0; i < len(s1) && diff == 0; i++ {
			diff = int(s1[i]) - int(s2[i])
		}
		return diff < 0
	}
}



func (v LatticeMap) String() string {
	var ret string

	keys := stringslice{}

	for k := range v{
		keys = append(keys,k)
	}

	sort.Sort(keys)

	for _,k := range keys{
		ret += v[k].String() + "\n"
	}

	return ret

}


func (v stringslice) Len() int {
	return len(v)
}

func (v stringslice) Swap(i, j int) {
	v[i],v[j] = v[j],v[i]
}

func (v stringslice) Less(i, j int) bool {

	s1 := v[i]
	s2 := v[j]
	if len(s1) != len(s2){
		return len(s1) < len(s2)
	}else{
		diff := 0
		for i := 0; i < len(s1) && diff == 0; i++ {
			diff = int(s1[i]) - int(s2[i])
		}
		return diff < 0
	}
}

