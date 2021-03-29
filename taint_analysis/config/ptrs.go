package config

import (
	"chaincode-checker/taint_analysis/utils"
	"go/token"
	"go/types"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
	"sort"
	"strings"
)

func (p *Project) SetPtrResult() {
	var err error
	p.PtrResult,err = pointer.Analyze(p.PtrConfig)

	if err != nil{
		log.Fatalf("pointer analyze failed. %s",err.Error())
	}

	for val,ptr := range p.PtrResult.Queries{
		var labels []string
		for _,label := range ptr.PointsTo().Labels(){
			labelname := label.Value().Name()
			labels = append(labels, labelname)
		}
		sort.Strings(labels)
		log.Debugf("%s, may point to: %s",val.Name(),labels)
	}

	for val,ptr := range p.PtrResult.IndirectQueries{
		var labels []string
		for _,label := range ptr.PointsTo().Labels(){
			labelname := label.Value().Name()
			labels = append(labels, labelname)
		}
		sort.Strings(labels)
		log.Debugf("%s, may indirect point to: %s",val.Name(),labels)
	}

	//log.Debug(p.PtrResult.Queries)
	log.Debug(p.PtrResult.IndirectQueries)
}

func (p *Project) SetPtrConfig(mains []*ssa.Package) {
	p.PtrConfig = &pointer.Config{
		Mains: mains,
		BuildCallGraph: false,
	}

	//p.addQuery(mains)
	p.addQueryMethods([]*ssa.Function{p.InvokeFunc})
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
					//log.Debugf("val:%s, %s",val.Name(),ptr.String())
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
								p.PtrConfig.AddIndirectQuery(ptrv)
							}
							//ok,indrectv := utils.IsIndirectPtr(val)
							//if ok{
							//	//log.Warningf("add query indirect:%s",indrectv.String())
							//	p.PtrConfig.AddIndirectQuery(indrectv)
							//}
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
						log.Warningf("add query:%s",ptrv.Name())
					}
					ok, indirectv := utils.IsIndirectPtr(val)
					if ok{
						p.PtrConfig.AddIndirectQuery(indirectv)
						log.Warningf("add query indirect:%s:%s",indirectv.Name(),indirectv.String())
					}
				}
			}
		}
	}
}


