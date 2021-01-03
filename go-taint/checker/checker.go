package checker

import (
	"chaincode-checker/go-taint/context"
	"chaincode-checker/go-taint/lattice"
	"chaincode-checker/go-taint/taint"
	"chaincode-checker/go-taint/utils"
	"github.com/op/go-logging"
	"github.com/pkg/errors"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
	logger "chaincode-checker/go-taint/logger"
)

var idCounter = 0
var log = logging.MustGetLogger("main")

type Checker struct {

	MainFunc *ssa.Function
	Program *ssa.Program




	pointerResult *pointer.Result
	pointerConfig *pointer.Config

	////The path to the .go-files starting at $GOPATH/src
	//Path              string
	////list of .go-files which should be analyzed
	//SourceFiles       []string
	////the file which holds the sources and sinks
	//SourceAndSinkFile string
	////analyze all pkgs?
	//Allpkgs           bool
	////Specify some packages in addition to the main package which should be analyzed
	//Pkgs              string
	////If is is set we perform a pointer analysis, else not
	//IsPtr             bool
	
	checkerCfg	*CheckerConfig

	ContextPkgs       []*ssa.Package
	ContextCallSuites []*context.ContextCallSuite
	Transitions       []*context.Transitions
	ValueCtxMap       *context.ValueContextMap
	ValToPtr          map[ssa.Value]pointer.Pointer

	ErrFlows *lattice.ErrInFlows
	taskList *TaskList

	//logfile *os.File
	
}


func NewChecker(path string, sourcefiles []string, sourceAndSinkFile string, allpkgs bool, pkgs string, ptr bool) *Checker {
	//ck := &checker{
	//	Path:              path,
	//	SourceFiles:       sourcefiles,
	//	SourceAndSinkFile: sourceAndSinkFile,
	//	Allpkgs:           allpkgs,
	//	Pkgs:              pkgs,
	//	IsPtr:             ptr,
	//}
	
	cc := NewCheckerConfig(path,sourcefiles,sourceAndSinkFile,allpkgs,pkgs,ptr)
	
	ck := &Checker{
		checkerCfg: cc,
	}
	return ck
}



func(ck *Checker) NewValueContext(function *ssa.Function) *context.ValueContext {
	if function == nil{
		log.Errorf("callee function is nil")
	}


	var lEntry, lExit lattice.Lattice

	if ck.checkerCfg.IsPtr {
		lEntry = lattice.NewLatticePointer(0, ck.ValToPtr)
		lExit = lattice.NewLatticePointer(0, ck.ValToPtr)
	} else {
		lEntry = lattice.NewLattice(0)
		lExit = lattice.NewLattice(0)
	}

	vi := context.NewValueCtxIndent(lEntry,function)
	vc := context.NewValueContext(vi,idCounter,lExit)

	idCounter++

	return vc

}

func (ck *Checker) NewCtxCallSuites(ctx *context.ValueContext, node ssa.Instruction) *context.ContextCallSuite {

	if ctx == nil || node == nil{
		return nil
	}

	var l1,l2 lattice.Lattice

	if ck.checkerCfg.IsPtr{
		l1 = lattice.NewLatticePointer(0,ck.ValToPtr)
		l2 = lattice.NewLatticePointer(0,ck.ValToPtr)
	}else{
		l1 = lattice.NewLattice(0)
		l2 = lattice.NewLattice(0)
	}

	ccs := context.NewContextCallSuite(ctx,node,l1,l2)

	ck.ContextCallSuites = append(ck.ContextCallSuites,ccs)
	return ccs

}

// An analysis state for the main function will be created.
// The context gets a value context for the main function. The entry and exit value is a empty lattice.
// The worklist consists of all instructions of the main function.
func(ck *Checker) initCtxVC(ssaFun *ssa.Function, vc *context.ValueContext) {
	pkg := ssaFun.Package()
	analyze := false
	// check whether the pkg is defined within the packages which should analyzed
ctxtfor:
	for _, p := range ck.ContextPkgs {
		if p == pkg {
			analyze = true
			break ctxtfor
		}
	}
	// only add the blocks and instructions if the package should be analyzed.
	if analyze {
		ssaFun.WriteTo(logger.LogFile)
		for _, block := range ssaFun.Blocks {
			for _, instr := range block.Instrs {
				// build a new context call site for every instruction within the main value context
				//log.Debugf("instr: %s",instr.String())
				c := ck.NewCtxCallSuites(vc, instr)
				ck.taskList.Add(c)
				//	ccsPool = append(ccsPool, c)
			}
		}
	}
}


func (ck *Checker) NewTransitions(start *context.ValueContext, targetContext *context.ValueContext, node ssa.Instruction) {
	if start == nil || targetContext == nil || node == nil {
		return
	}
	if start.Equal(targetContext) {
		return
	}
	t := context.NewTransition(start,targetContext,node)

	for _,a := range ck.Transitions {
		if a.Equal(t){
			return
		}
	}
	ck.Transitions = append(ck.Transitions,t)
}

func(ck *Checker) GetValueContext(callee *ssa.Function, pcaller []ssa.Value, lcaller lattice.Lattice, isClosure bool) *context.ValueContext{
	if callee == nil{
		return nil
		//TODO global value callee is not specify
	}

	latEntry := ck.matchParams(pcaller,lcaller,callee,isClosure)
	{
		c := ck.ValueCtxMap.FindInContext(callee,latEntry)
		if c != nil{
			return c
		}
	}

	log.Infof("latentry: %s",latEntry.String())

	{
		var sinkAndSources []*taint.TaintData
		sinkAndSources = utils.SS.Sources
		sinkAndSources = append(sinkAndSources, utils.SS.Sinks...)

		for i,s := range sinkAndSources{
			if s.IsInterface() {
				if callee.Signature.String() == s.GetSignature(){
					return nil
				}
			}else{
				if i == len(sinkAndSources) - 1{
					log.Infof("s string %s", s.String())
				}
				if callee.Signature.String() + " " + callee.String() == s.String(){
					return nil
				}
			}
		}
	}

	vc := ck.NewValueContext(callee)
	vc.ValueIndent.SetIn(latEntry)
	ck.ValueCtxMap.AddToContext(vc)
	log.Infof("new valuectx: %s",vc.String())
	//TODO init
	ck.initCtxVC(callee,vc)
	return vc
}






func (ck *Checker) StartAnalyzing() error {
	for !ck.taskList.Empty(){
		ccs := ck.taskList.RemoveFirstCCS()

		//TODO UPDATE
		err := ck.updateEntryContext(ccs)

		if err != nil{
			return errors.Wrapf(err,"failed update Entry ctx, %s",ccs.String())
		}
		//TODO FLOW
		if err := ck.Flow(ccs);err != nil{
			return errors.Wrap(err,"failed flow at function")
		}

		//TODO CHECK HANDLE CHANGE
		if err := ck.checkAndHandleChange(ccs);err != nil{
			return errors.Wrap(err,"error at checkAndHandleChange")
		}

		ck.checkAndHandleReturn(ccs)
	}

	if ck.ErrFlows.NumberOfFlows() > 0 {
		return ck.ErrFlows
	}
	return nil
}





