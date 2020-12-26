package checker

import (
	"chaincode-checker/go-taint/context"
	"chaincode-checker/go-taint/flows"
	"chaincode-checker/go-taint/lattice"
	"chaincode-checker/go-taint/taint"
	"chaincode-checker/go-taint/utils"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
	"log"
)

var idCounter = 0

type Checker struct {

	MainFunc *ssa.Function
	Program *ssa.Program

	ss *utils.SinkAndSources


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
	ValueCtxMap       context.ValueContextMap
	ValToPtr          map[ssa.Value]pointer.Pointer

	ErrFlows *flows.ErrInFlows
	
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
		log.Printf("callee function is nil")
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

func (ck *Checker) NewCtxCallSuites(isPtr bool, ctx *context.ValueContext, node ssa.Instruction) *context.ContextCallSuite {

	if ctx == nil || node == nil{
		return nil
	}

	var l1,l2 lattice.Lattice

	if isPtr{
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
	latEntry := matchParams(pcaller,lcaller,callee,isClosure,ck.checkerCfg.IsPtr,ck.ValToPtr)
	{
		c := ck.ValueCtxMap.FindInContext(callee,latEntry)
		if c != nil{
			return c
		}
	}


	{
		var sinkAndSources []*taint.TaintData
		sinkAndSources = ck.ss.Sinks
		sinkAndSources = append(sinkAndSources,ck.ss.Sources...)

		for i,s := range sinkAndSources{
			if s.IsInterface() {
				if callee.Signature.String() == s.GetSignature(){
					return nil
				}
			}else{
				if i == len(sinkAndSources) - 1{
					log.Printf("s string %s\n", s.String())
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
	log.Printf("new valuectx: %s",vc.String())
	//TODO init
	//initCtxVC(callee,vc)
	return vc
}



func matchParams(pcaller []ssa.Value, lcaller lattice.Lattice, callee *ssa.Function, isClosure bool, isPtr bool, valToPtr map[ssa.Value]pointer.Pointer) lattice.Lattice {


	var pcallee []ssa.Value

	if isClosure{
		fvs := callee.FreeVars
		pcallee = make([]ssa.Value,len(fvs))
		for i,fv := range fvs{
			pcallee[i] = fv
		}
	}else{
		params := callee.Params
		pcallee = make([]ssa.Value,len(params))
		for i,p := range params{
			pcallee[i] = p
		}
	}

	var ret lattice.Lattice

	if isPtr{
		ret = lattice.NewLatticePointer(0,valToPtr)
	}else{
		ret = lattice.NewLattice(0)
	}

	for i,val := range pcaller{
		ret.SetTag(pcallee[i],lcaller.GetTag(val))
	}

	return ret

}




