package ssautils

import (
	"github.com/pkg/errors"
	"go/types"
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

	mainpkg, err := TryBuild("chaincode-checker", []string{"../../chaincodes/timerandom/timerandomcc.go"})
	if err != nil{
		log.Debugf(err.Error())
	}

	mainpkg.WriteTo(os.Stdout)



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
	invokef.WriteTo(file)

	for _,block := range invokef.Blocks {
		dominees := block.Dominees()

		log.Infof("block index:%s -> idom:%s",block.Index,block.Idom())
		for _, dom := range dominees{

			log.Infof("block index:%s -> dominees:%s",block.Index, dom.String())
		}
	}

	return mainPkg, nil
}
