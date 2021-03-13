package checker

import (
	"chaincode-checker/taint_analysis/context"
	"chaincode-checker/taint_analysis/project_config"
	"chaincode-checker/taint_analysis/utils"
	"golang.org/x/tools/go/ssa"
)

var Config *CmdConfig
var TasksList *context.TaskList


func Init(path string, sourcefiles []string, sourceAndSinkFile string, allpkgs bool, pkgs string, ptr bool) {
	Config = NewCheckerConfig(path,sourcefiles,sourceAndSinkFile,allpkgs,pkgs,ptr)
	InitSSConfig()
	TasksList = context.NewTaskList()
	context.CallGraphs = context.NewCallGraphMap()
	//LatticeTable = make(map[string]latticer.Lattice)
	mainpkg := BuildSSA()
	mains := []*ssa.Package{mainpkg}

	setPkgsList(mainpkg)
	setupPtrs(mains)
	utils.ReplaceSend(mains)
	//init invoke function
	InitFunctionContext(project_config.WorkingProject.InvokeFunc)

}



func StartAnalyzing() error {
	for !TasksList.Empty(){
		ccs := TasksList.RemoveFront()

		log.Debugf("%s",ccs.String())

		//handle instr
		log.Debugf("handle instr: %s",ccs.GetInstr().String())


		//set lattice value tag according to instr args

		//

	}

	//if ck.ErrFlows.NumberOfFlows() > 0 {
	//	return ck.ErrFlows
	//}
	return nil
}

func Main(path string, sourcefiles []string, sourceAndSinkFile string, allpkgs bool, pkgs string, ptr bool){
	Init(path,sourcefiles,sourceAndSinkFile,allpkgs,pkgs,ptr)
	_ = StartAnalyzing()
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
