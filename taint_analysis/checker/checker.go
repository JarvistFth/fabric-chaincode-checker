package checker

import (
	"chaincode-checker/taint_analysis/Errors"
	"chaincode-checker/taint_analysis/config"
	"chaincode-checker/taint_analysis/context"
	"chaincode-checker/taint_analysis/logger"
)

var log = logger.GetLogger("./debuglogs/test")


func Init(path string, sourcefiles []string, sourceAndSinkFile string, allpkgs bool, pkgs string, ptr bool) {
	config.NewCmdConfig(path,sourcefiles,sourceAndSinkFile,allpkgs,pkgs,ptr)
	InitSSConfig()
	context.LatticeTable = make(context.LatticeMap)
	context.CallGraphs = context.NewCallGraphMap()
	Errors.NewErrSet()
	Errors.InitLevelMap()
	mainpkg := BuildSSA()

	setPkgsList(mainpkg)
	SetupPtrs(mainpkg)
	//utils.ReplaceSend(mains)
	//init invoke function

}



func StartAnalyzing()  {
	entryf := InitFunctionContext(config.InvokeFunc)

	//invokefn := config.WorkingProject.InvokeFunc



	//for _,block := range invokefn.Blocks{
	//
	//	preds := block.Preds
	//	succs := block.Succs
	//	var str string
	//	str += fmt.Sprintf("block:%d - preds: ",block.Index)
	//	for _,pred := range preds{
	//		str += fmt.Sprintf("block:%d ",pred.Index)
	//	}
	//	str += "\n"
	//	str += fmt.Sprintf("block:%d - succs: ",block.Index)
	//	for _,succ := range succs{
	//		str += fmt.Sprintf("block:%d ",succ.Index)
	//	}
	//	str += "\n"
	//	fmt.Println(str)
	//}



	entryf.LoopInstr()
	if !Errors.ErrorMsgPool.Empty() {
		Errors.ErrorMsgPool.Output()
	}
}

func Main(path string, sourcefiles []string, sourceAndSinkFile string, allpkgs bool, pkgs string, ptr bool){
	Init(path,sourcefiles,sourceAndSinkFile,allpkgs,pkgs,ptr)
	//os.Exit(0)
	//StartAnalyzing()

}
