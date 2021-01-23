package checker

import (
	"chaincode-checker/go-taint/context"
	"chaincode-checker/go-taint/lattice"
	"chaincode-checker/go-taint/ssautils"
	"chaincode-checker/go-taint/utils"
	"errors"
	"fmt"
	"go/token"
	"go/types"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
	"strings"
	//"log"
)


func (ck *Checker) Init()  {
	ck.makeAlloc()
	err := ck.initSSAandPTA()
	if err != nil{
		log.Errorf("error: %s",err.Error())
	}
	//ck.GetValueContext(ck.MainFunc,[]ssa.Value{},nil,false)
	//ck.GetValueContext(ck.InitFunc,[]ssa.Value{},nil,false)
	ck.GetValueContext(ck.InvokeFunc,[]ssa.Value{},nil,false)
}

func (ck *Checker) makeAlloc() {
	ck.ValueCtxMap = context.NewValueCtxMap()
	ck.ContextCallSuites = make([]*context.InstructionContext,0)
	ck.Transitions = make([]*context.Transitions,0)
	//ck.ValToPtr = make(map[ssa.Value]pointer.Pointer)
	ck.ContextPkgs = make([]*ssa.Package,0)
	ck.taskList = NewTaskList()
	ck.ErrFlows = lattice.NewErrInFlows()
	ValToPtrs = make(map[ssa.Value]pointer.Pointer)

}

func (ck *Checker) initSSAandPTA()  error {
	// First generating a ssautils with source code to get the main function
	var err error
	utils.SS,err = utils.ParseSourceAndSinkFile(ck.checkerCfg.SourceAndSinkFile)
	utils.HandleError(err, "ssautils build failed")
	log.Debugf("build path: %s source file: %s",ck.checkerCfg.Path,ck.checkerCfg.SourceFiles)
	mainpkg, err,initfn,invokefn := ssautils.Build(ck.checkerCfg.Path, ck.checkerCfg.SourceFiles)
	ck.InitFunc = initfn
	ck.InvokeFunc = invokefn
	utils.HandleError(err, "ssautils build failed")
	mainpkg.Build()
	log.Debugf("%s",utils.SS.String())


	ck.MainFunc = mainpkg.Func("main")


	if ck.MainFunc == nil{
		utils.HandleError(errors.New("no main function in pkgs"),"")
	}
	if ck.checkerCfg.Allpkgs{
		ck.ContextPkgs = ck.MainFunc.Prog.AllPackages()
	}else{
		log.Infof("only analyze main pkgs")
		ck.ContextPkgs = []*ssa.Package{mainpkg}
		if ck.checkerCfg.Pkgs != ""{
			for _,pkg := range strings.Split(ck.checkerCfg.Pkgs,","){
				p := ck.MainFunc.Prog.ImportedPackage(pkg)
				if p != nil{
					ck.ContextPkgs = append(ck.ContextPkgs,p)
				}else{
					log.Infof("pkg: [%s] is unknown in %s",pkg,ck.MainFunc.String())
					utils.HandleError(errors.New(fmt.Sprintf("pkg: [%s] is unknown in %s",pkg,ck.MainFunc.String())),"")
				}
			}
		}
	}
	var methods []*ssa.Function
	methods = append(methods,ck.InitFunc,ck.InvokeFunc)
	//setup pointer analysis
	mains := []*ssa.Package{mainpkg}
	ck.setupPointers(mains)
	ck.addQueryMethods(methods)
	ck.pointerResult,err = pointer.Analyze(ck.pointerConfig)
	//for k,v := range ck.pointerResult.Queries{
	//	log.Infof("value: %s, ptr: %s",k.Name(),v.PointsTo().String())
	//}

	//for k,v := range ck.pointerResult.IndirectQueries{
	//	log.Infof("indirect value: %s, ptr: %s",k.Name(),v.PointsTo().String())
	//}
	utils.HandleError(err,"pointer analysis failed\n")
	ck.setupPtrMap(mains)

	utils.ReplaceSend(mains)
	return nil
	
}

func (ck *Checker) setupPointers(mains []*ssa.Package) {
	ck.pointerConfig = &pointer.Config{
		Mains:          mains,
		BuildCallGraph: false,
	}
	ck.addQueries(mains)


}

func (ck *Checker) addQueries(mains []*ssa.Package) {
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
								ck.pointerConfig.AddQuery(ptrv)
							}
							ok,indrectv := utils.IsIndirectPtr(val)
							if ok{
								//log.Warningf("add query indirect:%s",indrectv.String())
								ck.pointerConfig.AddIndirectQuery(indrectv)
							}
						}
					}
				}
			}
		}
	}


}

func (ck *Checker) addQueryMethods(functions []*ssa.Function) {
	for _,f := range functions{
		for _,b := range f.Blocks{
			for _,i := range b.Instrs{
				val,ok := i.(ssa.Value)
				if ok{
					ok,ptrv := utils.IsPointerVal(val)
					if ok{
						ck.pointerConfig.AddQuery(ptrv)
						log.Warningf("add query:%s",ptrv.String())

					}
					ok, indirectv := utils.IsIndirectPtr(val)
					if ok{
						ck.pointerConfig.AddIndirectQuery(indirectv)
						log.Warningf("add query indirect:%s",indirectv.String())
					}
				}
			}
		}
	}
}



func (ck *Checker) setupPtrMap(pkgs []*ssa.Package) {
	for _,pkg := range pkgs{
		pkgstr := pkg.String()
		for _,p := range ck.ContextPkgs{
			if ok := strings.Contains(pkgstr,p.String());ok{
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
											ptr := ck.pointerResult.Queries[val]
											ck.ValToPtr[val] = ptr
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
															ptr := ck.pointerResult.IndirectQueries[val]
															ck.ValToPtr[val] = ptr
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

	//for val,ptr := range ck.ValToPtr{
	//
	//	log.Debugf("val to ptr map: %s, %s ,%s",val.Name(), val.String(),ptr.String())
	//}

	for val,ptr := range  ck.pointerResult.Queries{
		log.Debugf("ck.pointerResult.Queries %s=%s, %s",val.Name(), val.String(),ptr.PointsTo().String())
	}

	for val,ptr := range  ck.pointerResult.IndirectQueries{
		log.Debugf("ck.pointerResult.IndirectQueries %s=%s, %s", val.Name(),val.String(),ptr.PointsTo().String())
	}
}
