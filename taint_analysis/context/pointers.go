package context

import (
	"chaincode-checker/taint_analysis/config"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
)

func CheckAlias(val ssa.Value) (bool,[]ssa.Value){
	//ret,ok := config.WorkingProject.ValToPtrs[val]

	rets := make([]ssa.Value,0)
	haveAlias := false
	ok := pointer.CanPoint(val.Type())
	if ok{
		ptr,ok := config.ValToPtrs[val]
		if ok{
			for v,p := range config.ValToPtrs{
				if ptr.MayAlias(p){
					haveAlias = true
					log.Debugf("%s may alias %s",val.Name(),v.Name())
					rets = append(rets,v)
				}
			}
		}
	}
	return haveAlias,rets
}