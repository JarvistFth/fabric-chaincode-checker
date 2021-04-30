package config

import (
	"chaincode-checker/taint_analysis/utils"
	"fmt"
	"go/token"
	"go/types"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
)

func analyzePtr(cfg *pointer.Config, fn *ssa.Function) *pointer.Result{
	var err error
	result,err := pointer.Analyze(cfg)

	//PtrResults[utils.GenFuncID(fn)] = result

	if err != nil{
		panic(fmt.Sprintf("pointer analyze failed. %s",err.Error()))
		return nil
	}
	return result
	//for val,ptr := range p.PtrResult.Queries{
	//	var labels []string
	//	for _,label := range ptr.PointsTo().Labels(){
	//		labelname := label.Value().Name()
	//		labels = append(labels, labelname)
	//	}
	//	sort.Strings(labels)
	//	log.Debugf("%s, may point to: %s",val.Name(),labels)
	//}
	//
	//for val,ptr := range p.PtrResult.IndirectQueries{
	//	var labels []string
	//	for _,label := range ptr.PointsTo().Labels(){
	//		labelname := label.Value().Name()
	//		labels = append(labels, labelname)
	//	}
	//	sort.Strings(labels)
	//	log.Debugf("%s, may indirect point to: %s",val.Name(),labels)
	//}

	//log.Debug(p.PtrResult.Queries)
	//log.Debug(p.PtrResult.IndirectQueries)
}

func GetPtrCfg( fn*ssa.Function, mains ...*ssa.Package) *pointer.Config{
	cfg := &pointer.Config{
		Mains: mains,
		BuildCallGraph: false,
	}
	//AddQueryInFunction(cfg,fn)
	for _,pkg := range mains{
		for name,mem := range pkg.Members{
			if mem.Token() == token.FUNC{
				if mem.Name()  != "Clearenv" && mem.Name() != "init"{
					fn := pkg.Func(name)
					log.Debugf("func:%s start add query",fn.Name())
					AddQueryInFunction(cfg,fn)
				}
			}
		}
	}
	return cfg
}
//
//func SetPtrConfig(mains []*ssa.Package) {
//	p.PtrConfig = &pointer.Config{
//		Mains: mains,
//		BuildCallGraph: false,
//	}
//
//	//p.addQuery(mains)
//	p.addQueryMethods([]*ssa.Function{p.InvokeFunc})
//}

func AddValToPtrs(result *pointer.Result, fn *ssa.Function) {
	for _,b := range fn.Blocks{
		for _,i := range b.Instrs{
			if val,ok := i.(ssa.Value);ok{
				ok = pointer.CanPoint(val.Type())
				if ok{
					ptr := result.Queries[val]
					ValToPtrs[val] = ptr
				}else{
					//todo indirect queries
					if val.Type() != nil{
						if _,ok := val.(*ssa.Range);!ok{
							if val.Type().Underlying() != nil{
								tp, ok := val.Type().Underlying().(*types.Pointer)
								if ok {
									ok = pointer.CanPoint(tp.Elem())
									if ok {
										ptr := result.IndirectQueries[val]
										ValToPtrs[val] = ptr
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
	}

	for k,v := range ValToPtrs{
		for k1,v1 := range ValToPtrs{
			if v.MayAlias(v1){
				log.Debugf("%s may alias %s\n",k.Name(), k1.Name())
			}
		}
	}
}

func SetValToPtrs(result *pointer.Result) {
	method := InvokeFunc
	log.Debug("start set val to ptrs!!")
	for _,b := range method.Blocks{
		for _, i := range b.Instrs{
			val,ok := i.(ssa.Value)
			if ok{
				ok = pointer.CanPoint(val.Type())
				if ok{
					ptr := result.Queries[val]
					ValToPtrs[val] = ptr
					//log.Debugf("val:%s, %s",val.Name(),ptr.String())
				}else{
					if val.Type() != nil{
						if _,ok := val.(*ssa.Range);!ok{
							if val.Type().Underlying() != nil{
								tp, ok := val.Type().Underlying().(*types.Pointer)
								if ok {
									ok = pointer.CanPoint(tp.Elem())
									if ok {
										ptr := result.IndirectQueries[val]
										ValToPtrs[val] = ptr
										log.Debugf("val:%s, %p",val.Name(),ptr.String())
									} else {
										// tp.Elem() is not a pointer -> nothing to do
									}
								}
							}
						}
					}
				}
				//todo: means?
			}

		}
	}

}

func AddQueryInFunction(cfg *pointer.Config, f *ssa.Function){
	for _,b := range f.Blocks{
		for _,i := range b.Instrs{
			val,ok := i.(ssa.Value)
			if ok{
				ok,ptrv := utils.IsPointerVal(val)
				if ok{
					cfg.AddQuery(ptrv)
					//log.Warningf("add query:%s",ptrv.Name())
				}
				ok, indirectv := utils.IsIndirectPtr(val)
				if ok{
					cfg.AddIndirectQuery(indirectv)
					//log.Warningf("add query indirect:%s:%s",indirectv.Name(),indirectv.String())
				}
			}
		}
	}
}

func UpdatePtrResultAndMap(cfg *pointer.Config, fn *ssa.Function) *pointer.Result{
	result := analyzePtr(cfg,fn)
	PtrResult = result
	AddValToPtrs(result,fn)
	return result
}


