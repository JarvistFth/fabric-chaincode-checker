package ssautils

import (
	"github.com/pkg/errors"
	"golang.org/x/tools/go/loader"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
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
	var ret []*ssa.Package
	ret = append(ret,mainPkg)

	return mainPkg, nil
}
