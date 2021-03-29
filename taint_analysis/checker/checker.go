package checker

import (
	"chaincode-checker/taint_analysis/Errors"
	"chaincode-checker/taint_analysis/config"
	"chaincode-checker/taint_analysis/context"
	"chaincode-checker/taint_analysis/logger"
	"chaincode-checker/taint_analysis/utils"
	"fmt"
	"golang.org/x/tools/go/ssa"
)

var log = logger.GetLogger("./debuglogs/test")


func Init(path string, sourcefiles []string, sourceAndSinkFile string, allpkgs bool, pkgs string, ptr bool) {
	config.NewCmdConfig(path,sourcefiles,sourceAndSinkFile,allpkgs,pkgs,ptr)
	InitSSConfig()
	context.CallGraphs = context.NewCallGraphMap()
	Errors.ErrMsgPool = Errors.NewErrMessages()

	mainpkg := BuildSSA()
	mains := []*ssa.Package{mainpkg}

	setPkgsList(mainpkg)
	SetupPtrs(mains)
	utils.ReplaceSend(mains)
	//init invoke function

}



func StartAnalyzing()  {
	entryf := InitFunctionContext(config.WorkingProject.InvokeFunc)

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
	if !Errors.ErrMsgPool.Empty() {
		fmt.Print(Errors.ErrMsgPool.String())
	}
}

func Main(path string, sourcefiles []string, sourceAndSinkFile string, allpkgs bool, pkgs string, ptr bool){
	Init(path,sourcefiles,sourceAndSinkFile,allpkgs,pkgs,ptr)
	StartAnalyzing()
	//if err != nil {
	//	switch err := err.(type) {
	//	case *latticer.ErrInFlows:
	//		fmt.Printf("err.NumberOfFlows: %d, messages are: \n", err.NumberOfFlows())
	//		fmt.Printf("%s\n", err.Error())
	//	default:
	//		log.Errorf("Errors: %+v\n", err)
	//		os.Exit(1)
	//	}
	//} else {
	//	fmt.Printf("Gongrats. Gotcha has not found an error.\n")
	//	os.Exit(0)
	//}
}
