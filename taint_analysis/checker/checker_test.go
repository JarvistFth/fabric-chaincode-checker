package checker

import (
	"chaincode-checker/taint_analysis/Errors"
	"chaincode-checker/taint_analysis/config"
	"chaincode-checker/taint_analysis/context"
	"chaincode-checker/taint_analysis/logger"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"golang.org/x/tools/go/loader"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
	"os"
	"strings"
	"testing"
)

var ssf = "../../config/sourceandsink.json"
var path = "chaincode-checker"
var allpkgs = false
var ptr = true
var pkgs = ""

type sourcefiles []string
var sourceFilesFlag = []string{"../../chaincodes/gocc/gocc.go"}

//var sourceFilesFlag = []string{"../../chaincodes/timerandom/timerandomcc.go"}

func TestBuild(t *testing.T) {
	//mainpkgs, err := TryBuild("chaincode-checker", []string{"../../chaincodes/simple.go"})

	mainpkg, err := TryBuild("chaincode-checker", []string{"../../chaincodes/timerandom/timerandomcc.go"})
	if err != nil{
		log.Debugf(err.Error())
	}

	mainpkg.WriteTo(os.Stdout)

	//mains := []*ssa.Package{mainpkg}
	setPkgsList(mainpkg)
	SetupPtrs(mainpkg)

	//mainpkg.WriteTo(os.Stdout)



}

func TryBuild(path string, sourcefiles []string) (*ssa.Package, error){
	var conf loader.Config
	srcfs := strings.Join(sourcefiles, ", ")
	conf.CreateFromFilenames(path, srcfs)

	lprog, err := conf.Load()
	if err != nil {
		return nil, errors.Errorf("fail to load config of path: %s and sourcefiles: %s", path, srcfs)
	}

	prog := ssautil.CreateProgram(lprog, ssa.SanityCheckFunctions)

	for _,c := range lprog.Created{
		log.Debugf(c.String())
	}
	mainPkg := prog.Package(lprog.Created[0].Pkg)


	prog.Build()
	mainPkg.Build()
	var ret []*ssa.Package
	ret = append(ret,mainPkg)

	s := mainPkg.Type("SimpleAsset")
	t := s.Type()

	p := types.NewPointer(t)


	//initf := prog.LookupMethod(p,mainPkg.Pkg,"Init")
	invokef := prog.LookupMethod(p,mainPkg.Pkg,"Invoke")
	invokef.WriteTo(logger.LogFile)

	for _,block := range invokef.Blocks {
		dominees := block.Dominees()

		log.Infof("block index:%s -> idom:%s",block.Index,block.Idom())
		for _, dom := range dominees{

			log.Infof("block index:%s -> dominees:%s",block.Index, dom.String())
		}
	}

	return mainPkg, nil
}

func TestStart(t *testing.T) {
	Main(path,sourceFilesFlag,ssf,allpkgs,pkgs,ptr)

}

func TestBuildSSA(t *testing.T){
	config.NewCmdConfig(path,sourceFilesFlag,ssf,allpkgs,pkgs,ptr)
	InitSSConfig()
	context.CallGraphs = context.NewCallGraphMap()
	Errors.InitLevelMap()
	BuildSSA()
	//mains := []*ssa.Package{mainpkg}
	//
	//setPkgsList(mainpkg)
	//SetupPtrs(mains)
	//utils.ReplaceSend(mains)
	if !Errors.ErrorMsgPool.Empty() {
		Errors.ErrorMsgPool.Output()
	}
}

func TestAST(t *testing.T){
	fset := token.NewFileSet()

	f, err := parser.ParseFile(fset, "../../chaincodes/gocc/gocc.go", nil, parser.ParseComments)
	if err != nil {
		panic(err)
	}

	ast.Inspect(f, func(n ast.Node) bool {
		// Find Return Statements
		ret, ok := n.(*ast.ReturnStmt)
		if ok {
			fmt.Printf("return statement found on line %v:\n", fset.Position(ret.Pos()))
			return true
		}
		return true
	})
}

func TestJson(t *testing.T){
	out := Errors.ErrorMsgOut{
		Pos:   "1",
		Level: "2",
		Rules: "33",
	}
	out2 := Errors.ErrorMsgOut{
		Pos:   "1",
		Level: "22",
		Rules: "33",
	}

	outs := new(Errors.ErrorMsgOuts)
	outs.Outs = append(outs.Outs,out,out2)

	jsonres,err := json.MarshalIndent(outs,"","\t")
	if err != nil{
		fmt.Println(err.Error())
	}else{
		fmt.Println(string(jsonres))
	}

}

