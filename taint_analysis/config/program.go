package config

import (
	"github.com/op/go-logging"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
)

var log = logging.MustGetLogger("Main")

//var WorkingProject *Project


var (
	Program *ssa.Program
	Packages []*ssa.Package
 	InvokeFunc *ssa.Function
	InitFunc *ssa.Function
	Methods []*ssa.Function
	//PtrResults map[string]*pointer.Result
	PtrResult *pointer.Result
	//PtrConfig *pointer.Config
	ValToPtrs map[ssa.Value]pointer.Pointer
	PtrCfg *pointer.Config
	MainPkg *ssa.Package
)



func NewProjecet(prog *ssa.Program, initfn,invokefn *ssa.Function){
	Program = prog
	InitFunc = initfn
	InvokeFunc = invokefn

	//PtrResults =
	ValToPtrs = make(map[ssa.Value]pointer.Pointer)
}


func SetPkgs(pkgs []*ssa.Package) {
	Packages = pkgs
}
//
//type Project struct {
//
//	//MainFunc *ssa.Function
//	Program *ssa.Program
//	Packages []*ssa.Package
//
//	InvokeFunc *ssa.Function
//	InitFunc *ssa.Function
//	Methods []*ssa.Function
//
//	PtrResult *pointer.Result
//	PtrConfig *pointer.Config
//
//	ValToPtrs map[ssa.Value]pointer.Pointer
//}




type stringslice []string

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

//
//func GetProject(invokefn, initfn *ssa.Function) *Project {
//	var methods []*ssa.Function
//	methods = append(methods,initfn,invokefn)
//
//	p := &Project{
//		//MainFunc:   nil,
//		Program: nil,
//		Packages:   nil,
//		InvokeFunc: invokefn,
//		InitFunc:   initfn,
//		PtrResult:  nil,
//		PtrConfig:  nil,
//		ValToPtrs:  nil,
//		Methods: methods,
//	}
//	p.malloc()
//	return p
//}
//
//func (p *Project) malloc() {
//	p.ValToPtrs = make(map[ssa.Value]pointer.Pointer)
//}
//
//func (p *Project) SetProgram(prog *ssa.Program) {
//	p.Program = prog
//}

//func (p *Project) Setpkgs(pkgs []*ssa.Package)  {
//	p.Packages = pkgs
//}
