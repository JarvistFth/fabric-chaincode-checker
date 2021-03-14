package checker

import (
	"chaincode-checker/taint_analysis/config"
	"chaincode-checker/taint_analysis/context"
	"golang.org/x/tools/go/ssa"
)

func InitFunctionContext(ssaFunc *ssa.Function) *context.CallGraph {
	f,_ := context.GetFunctionContext(ssaFunc,false,config.Config.WithPtr)
	log.Debugf("init function: %s",f.GetName())
	return f
}

