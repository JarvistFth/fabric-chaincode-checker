package ssautils

import (
	"github.com/pkg/errors"
	"go/token"
	"go/types"
	"golang.org/x/tools/go/loader"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
	"golang.org/x/tools/go/types/typeutil"
	"os"
	"strings"
	"testing"
)

var file, _ = os.OpenFile("one.log",os.O_APPEND|os.O_WRONLY|os.O_CREATE,0666)

type members []ssa.Member

func TestBuild(t *testing.T) {
	//mainpkgs, err := TryBuild("chaincode-checker", []string{"../../chaincodes/simple.go"})
	mainpkg, err := TryBuild("chaincode-checker", []string{"../../chaincodes/globalcc/globalcc.go"})
	if err != nil{
		log.Debugf(err.Error())
	}


	mainpkg.Build()
	//mainpkg.WriteTo(os.Stdout)
	funcs := members([]ssa.Member{})
	for _, obj := range mainpkg.Members {
		if obj.Token() == token.FUNC {
			funcs = append(funcs, obj)
		}
	}




	// sort by Pos()
	//for _, f := range funcs {
	//	mainpkg.Func(f.Name()).WriteTo(os.Stdout)
	//}

	for _,t := range mainpkg.Members{
		if t.Token() == token.STRUCT{
			//mainpkg.Type(t.Name()).Object()

			for _, meth := range typeutil.IntuitiveMethodSet(t.Type(), &mainpkg.Prog.MethodSets) {
				log.Debugf( "    %s\n", types.SelectionString(meth, types.RelativeTo(mainpkg.Pkg)))
			}
		}

	}


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

	//members := mainPkg.Members
	//for _,v := range members{
	//
	//	if g,ok := v.(*ssa.Global);ok{
	//		s := g.Name()
	//		if s == "init$guard"{
	//			continue
	//		}
	//		//TODO take it into sources
	//		utils.TakeGlobalVarToSources(s)
	//		log.Debugf(s)
	//	}
	//}
	prog.Build()
	var ret []*ssa.Package
	ret = append(ret,mainPkg)

	return mainPkg, nil
}
