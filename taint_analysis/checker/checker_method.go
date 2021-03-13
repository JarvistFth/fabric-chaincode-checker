package checker

import (
	"chaincode-checker/taint_analysis/context"
	"golang.org/x/tools/go/ssa"
)

func InitFunctionContext(ssaFunc *ssa.Function) {
	f,_ := context.GetFunctionContext(ssaFunc,false,Config.IsPtr)
	log.Debugf("init function: %s",f.GetName())

	//analyzeFuntionCtx(ssaFunc,f)
}

