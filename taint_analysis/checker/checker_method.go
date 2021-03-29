package checker

import (
	"chaincode-checker/taint_analysis/config"
	"chaincode-checker/taint_analysis/context"
	"chaincode-checker/taint_analysis/latticer"
	"golang.org/x/tools/go/ssa"
)

func InitFunctionContext(ssaFunc *ssa.Function) *context.CallGraph {
	initParamsLattices := make(latticer.Lattices,0)
	for _,params := range ssaFunc.Params{
		newlat := latticer.NewLatticePointer(params,config.WorkingProject.ValToPtrs)
		initParamsLattices = append(initParamsLattices,newlat)
	}
	f,_ := context.GetFunctionContext(ssaFunc,false,config.Config.WithPtr,initParamsLattices)
	log.Debugf("init function: %s",f.GetName())
	return f
}



