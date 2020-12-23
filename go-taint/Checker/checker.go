package Checker

import (
	"chaincode-checker/go-taint/Context"
	"chaincode-checker/go-taint/lattice"
	"chaincode-checker/go-taint/ssautils"
	"chaincode-checker/go-taint/utils"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
	"log"
	"strings"
)

var idCounter = 0

type Checker struct {

	MainFunc *ssa.Function
	Program *ssa.Program
	Config utils.Config

	PointerResult *pointer.Result
	PointerConf *pointer.Config
	ContextPkgs []*ssa.Package

	ValToPtr map[ssa.Value]pointer.Pointer
	
	Path              string
	SourceFiles       []string
	SourceAndSinkFile string
	Allpkgs           bool
	Pkgs              string
	IsPtr             bool


	ContextCallSuites []*Context.ContextCallSuite
	Transitioins []*Context.Transitions

	
	
}


func NewChecker(path string, sourcefiles []string, sourceAndSinkFile string, allpkgs bool, pkgs string, ptr bool) *Checker {
	ck := &Checker{
		Path:              path,
		SourceFiles:       sourcefiles,
		SourceAndSinkFile: sourceAndSinkFile,
		Allpkgs:           allpkgs,
		Pkgs:              pkgs,
		IsPtr:             ptr,
	}
	return ck
}

func (ck *Checker) Init()  {
	
}

func (ck *Checker) initSSAandPTA() (*ssa.Function, error) {
	// First generating a ssautils with source code to get the main function
	mainpkg, err := ssautils.Build(ck.Path, ck.SourceFiles)
	handleError(err, "ssautils build failed")
	mainpkg.Build()
	ck.MainFunc = mainpkg.Func("main")
	handleError(errors.New("no main() function found!"), "")
	vcs = &VCS{ctx: make(map[VcIdentifier]*ValueContext, 0)}
	worklist = NewWlList()
	ccsPool = make([]*ContextCallSite, 0)
	transitions = make([]*Transition, 0)
	// Initialize the Sources and Sinks Slices with the help of the sources and sinks file
	err = utils.ParseSourceAndSinkFile(ck.SourceAndSinkFile)
	handleError(err, "reading source and sink file failed")
	log.Printf("sources: %v\n", ck.Config.Sources)
	log.Printf("sinks: %v\n", ck.Config.Sinks)

	// Add only the packages which are defined by the arguemnts
	// Flag allpkgs analyze all possible packages. If the flag is not set, it could be that a certain amound of packages are defined in pkgs.
	if allpkgs {
		contextpkgs = mainFunc.Prog.AllPackages()
	} else {
		log.Printf("mainpkg %v", mainpkg)
		contextpkgs = []*ssa.Package{mainpkg}
		//log.Printf("Name of mainpkg: %s\n", contextpkgs[0].String())
		// If manuelly pkgs are passed with the pkgs argument: Add these packages.
		if pkgs != "" {
			for _, pkg := range strings.Split(pkgs, ",") {
				p := mainFunc.Prog.ImportedPackage(pkg)
				// p is nil if no ssautils package for the string pkg is created
				// TODO "improve" handling (=/= ignoring)
				if p != nil {
					contextpkgs = append(contextpkgs, p)
				} else {
					log.Printf("Pkg [%s] is unknown in %s", pkg, mainFunc.String())
					handleError(errors.New("Pkg ["+pkg+"] is unknown in "+mainFunc.String()), "")
				}
			}
		}
	}
	log.Printf("Analyze: %d : packages(%v)\n", len(contextpkgs), contextpkgs)
	stat.Printf("#packages, %d,", len(contextpkgs))

	// Setup and analyze pointers
	// pointer analysis needs a package with a main function
	setupPTA([]*ssa.Package{mainpkg})
	pta, err = pointer.Analyze(conf)
	handleError(err, "pointer analysis failed")
	setPtrMap([]*ssa.Package{mainpkg})

	// Replace ssautils.Send with Send
	ssabuilder.ReplaceSend(contextpkgs)

	return mainFunc, nil
}



func(ck *Checker) NewValueContext(function *ssa.Function) *Context.ValueContext {
	if function == nil{
		log.Printf("callee function is nil")
	}


	var lEntry, lExit lattice.Lattice

	if ck.IsPtr {
		lEntry = lattice.NewLatticePointer(0, ck.ValToPtr)
		lExit = lattice.NewLatticePointer(0, ck.ValToPtr)
	} else {
		lEntry = lattice.NewLattice(0)
		lExit = lattice.NewLattice(0)
	}

	vc := &Context.ValueContext{
		ValueIdentInterface: &Context.ValueContextIndent{
			In:       lEntry,
			Function: function,
		},
		ExitValue: lExit,
		Id:        idCounter,
	}
	idCounter++


	return vc

}

func (ck *Checker)NewCtxCallSuite(isPtr bool, ctx *Context.ValueContext, node ssa.Instruction) *Context.ContextCallSuite {

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

	ccs := &Context.ContextCallSuite{
		ctx,node,l1,l2,
	}

	ck.ContextCallSuites = append(ck.ContextCallSuites,ccs)
	return ccs

}



