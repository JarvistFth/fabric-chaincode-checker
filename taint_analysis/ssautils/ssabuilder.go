package ssautils

import (
	"chaincode-checker/taint_analysis/logger"
	"fmt"
	"github.com/pkg/errors"
	"go/token"
	"go/types"
	"golang.org/x/tools/go/loader"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
	"strings"
)

var log = logger.GetLogger("./debuglogs/test")


func Build(path string, sourcefiles []string) (*ssa.Package, error, *ssa.Function, *ssa.Function, *ssa.Program){
	var conf loader.Config
	//srcfs := strings.Join(sourcefiles, ", ")
	conf.CreateFromFilenames(path, sourcefiles...)
	//log.Infof("srcfs: %s",srcfs)
	lprog, err := conf.Load()
	if err != nil {
		return nil, errors.Errorf("fail to load config of path: %s and sourcefiles: %s", path, sourcefiles),nil,nil,nil
	}

	prog := ssautil.CreateProgram(lprog, ssa.SanityCheckFunctions)


	mainPkg := prog.Package(lprog.Created[0].Pkg)

	prog.Build()

	var initf *ssa.Function

	s := mainPkg.Type("SimpleAsset")
	t := s.Type()

	p := types.NewPointer(t)


	initf = prog.LookupMethod(p,mainPkg.Pkg,"Init")
	invokef := prog.LookupMethod(p,mainPkg.Pkg,"Invoke")
	//initf.WriteTo(os.Stdout)

	fmt.Println("end build ssa pkgs")
	return mainPkg, nil, initf, invokef,prog

}

// ReplaceSend replaces the ssautils.Send with the Send implemented in this package
func ReplaceSend(pkgs []*ssa.Package) {
	chToFuncs := findChannels(pkgs)
	for _, pkg := range pkgs {
		for name, memb := range pkg.Members {
			if memb.Token() == token.FUNC {
				f := pkg.Func(name)
				for _, b := range f.Blocks {
					for n, i := range b.Instrs {
						val, ok := i.(*ssa.Send)
						if ok {
							replace := &Send{&send{val, chToFuncs[val.Chan]}}
							b.Instrs[n] = replace
						}
					}
				}
			}
		}
	}
}

// fincChannels finds for all channels the corresponding call instructions
func findChannels(mains []*ssa.Package) map[ssa.Value][]ssa.CallInstruction {
	var callCom *ssa.CallCommon
	chfuncs := make(map[ssa.Value][]ssa.CallInstruction, 0)
	for _, pkg := range mains {
		for name, memb := range pkg.Members {
			if memb.Token() == token.FUNC {
				f := pkg.Func(name)
				for _, b := range f.Blocks {
					for _, i := range b.Instrs {
						callCom = nil
						switch it := i.(type) {
						case *ssa.Go:
							callCom = it.Common()
						case *ssa.Defer:
							callCom = it.Common()
						case *ssa.Call:
							callCom = it.Common()
						}
						if callCom != nil {
						args:
							for _, v := range callCom.Args {
								mc, ok := v.(*ssa.MakeChan)
								i, _ := i.(ssa.CallInstruction)
								if ok {
									calls := chfuncs[mc]
									if calls == nil {
										calls = make([]ssa.CallInstruction, 0)
									}
									chfuncs[mc] = append(calls, i)
									continue args
								}
								// TODO: find better solution
								underly := v.Type().Underlying()
								isChan := strings.Contains(underly.String(), "chan")
								if isChan {
									calls := chfuncs[v]
									if calls == nil {
										calls = make([]ssa.CallInstruction, 0)
									}
									chfuncs[v] = append(calls, i)
								}
							}
						}
					}
				}
			}
		}
	}
	return chfuncs
}
