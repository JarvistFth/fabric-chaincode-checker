package project_config

import (
	"chaincode-checker/taint_analysis/utils"
	"github.com/op/go-logging"
	"go/token"
	"go/types"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
	"strings"
)

var log = logging.MustGetLogger("Main")

var WorkingProject *Project


type Project struct {

	//MainFunc *ssa.Function
	Program *ssa.Program
	Packages []*ssa.Package

	InvokeFunc *ssa.Function
	InitFunc *ssa.Function
	Methods []*ssa.Function

	PtrResult *pointer.Result
	PtrConfig *pointer.Config

	ValToPtrs map[ssa.Value]pointer.Pointer

}

func GetProject(invokefn, initfn *ssa.Function) *Project {
	var methods []*ssa.Function
	methods = append(methods,initfn,invokefn)

	p := &Project{
		//MainFunc:   nil,
		Program: nil,
		Packages:   nil,
		InvokeFunc: invokefn,
		InitFunc:   initfn,
		PtrResult:  nil,
		PtrConfig:  nil,
		ValToPtrs:  nil,
		Methods: methods,
	}
	p.malloc()
	return p
}

func (p *Project) malloc() {
	p.ValToPtrs = make(map[ssa.Value]pointer.Pointer)
}

func (p *Project) SetProgram(prog *ssa.Program) {
	p.Program = prog
}

func (p *Project) Setpkgs(pkgs []*ssa.Package)  {
	p.Packages = pkgs
}

func (p *Project) SetPtrResult() {
	var err error
	p.PtrResult,err = pointer.Analyze(p.PtrConfig)
	if err != nil{
		log.Fatalf("pointer analyze failed. %s",err.Error())
	}
}

func (p *Project) SetPtrConfig(mains []*ssa.Package) {
	p.PtrConfig = &pointer.Config{
		Mains: mains,
		BuildCallGraph: false,
	}

	p.addQuery(mains)
	p.addQueryMethods(p.Methods)
}

func (p *Project) SetValToPtrs() {
	method := WorkingProject.InvokeFunc
	log.Debug("start set val to ptrs!!")
	for _,b := range method.Blocks{
		for _, i := range b.Instrs{
			val,ok := i.(ssa.Value)
			if ok{
				ok = pointer.CanPoint(val.Type())
				if ok{
					ptr := p.PtrResult.Queries[val]
					p.ValToPtrs[val] = ptr
					log.Debugf("val:%s, %s",val.Name(),ptr.String())
				}else{

				}
				if val.Type() != nil{
					if _,ok := val.(*ssa.Range);!ok{
						if val.Type().Underlying() != nil{
							tp, ok := val.Type().Underlying().(*types.Pointer)
							if ok {
								ok = pointer.CanPoint(tp.Elem())
								if ok {
									ptr := p.PtrResult.IndirectQueries[val]
									p.ValToPtrs[val] = ptr
									log.Debugf("val:%s, %p",val.Name(),ptr.String())
								} else {
									// tp.Elem() is not a pointer -> nothing to do
								}
							}
						}
					}
				}
			}

		}
	}

	for _,pkg := range p.Packages{
		pkgstr := pkg.String()
		for _, pkg := range p.Packages{
			if ok := strings.Contains(pkgstr, pkg.String());ok{

				members := pkg.Members
				for name,member := range members{
					if member.Token() == token.FUNC{
						if member.Name() != "Clearenv"{
							f := pkg.Func(name)
							for _,b := range f.Blocks{
								for _,i := range b.Instrs{
									val,ok := i.(ssa.Value)
									if ok {
										ok = pointer.CanPoint(val.Type())
										if ok{
											ptr := p.PtrResult.Queries[val]
											p.ValToPtrs[val] = ptr
										}else{
											//can not point, do nothing
										}
										if val.Type() != nil{
											if _,ok := val.(*ssa.Range); !ok{
												if val.Type().Underlying() != nil {
													tp, ok := val.Type().Underlying().(*types.Pointer)
													if ok {
														ok = pointer.CanPoint(tp.Elem())
														if ok {
															ptr := p.PtrResult.IndirectQueries[val]
															p.ValToPtrs[val] = ptr
														} else {
															// tp.Elem() is not a pointer -> nothing to do
														}
													}
												}
											}
										}
									}else{
										//end i.(ssa.value)
										// not all instructions are values.
										// the pointer analysis needs a value as parameter.
									}
								}//end instr
							}// range blocks
						}else{
							// ignore -> will crash
						}
					}else{
						//end token.FUNC
						// not interested in VAR, CONST and TYPE
					}
				}
			}else{
				//end pkgs.contain(),ok
				//pkgs not contain the interested one
				//
			}
		}//end ctx pkgs
	}
}

func(p *Project) addQuery(mains []*ssa.Package) {
	for _, pkg := range mains{
		for name,member := range pkg.Members{
			if member.Token() == token.FUNC{
				f := pkg.Func(name)
				for _,b := range f.Blocks{
					for _,i := range b.Instrs{
						val, ok := i.(ssa.Value)
						if ok {
							ok, ptrv := utils.IsPointerVal(val)
							if ok{
								//log.Warningf("add query:%s",ptrv.String())
								p.PtrConfig.AddQuery(ptrv)
							}
							ok,indrectv := utils.IsIndirectPtr(val)
							if ok{
								//log.Warningf("add query indirect:%s",indrectv.String())
								p.PtrConfig.AddIndirectQuery(indrectv)
							}
						}
					}
				}
			}
		}
	}
}

func (p *Project) addQueryMethods(functions []*ssa.Function) {
	for _,f := range functions{
		for _,b := range f.Blocks{
			for _,i := range b.Instrs{
				val,ok := i.(ssa.Value)
				if ok{
					ok,ptrv := utils.IsPointerVal(val)
					if ok{
						p.PtrConfig.AddQuery(ptrv)
						//log.Warningf("add query:%s",ptrv.String())

					}
					ok, indirectv := utils.IsIndirectPtr(val)
					if ok{
						p.PtrConfig.AddIndirectQuery(indirectv)
						//log.Warningf("add query indirect:%s",indirectv.String())
					}
				}
			}
		}
	}
}

