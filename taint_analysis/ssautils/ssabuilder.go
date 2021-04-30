package ssautils

import (
	"chaincode-checker/taint_analysis/Errors"
	"chaincode-checker/taint_analysis/logger"
	"github.com/pkg/errors"
	"go/token"
	"go/types"
	"golang.org/x/tools/go/loader"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
	"strings"
)

var log = logger.GetLogger("./debuglogs/test")
var internalPkgs map[string]struct{}

func Build(path string, sourcefiles []string) (*ssa.Package, error, *ssa.Function, *ssa.Function, *ssa.Program){
	initInternalPkg()
	var conf loader.Config
	//srcfs := strings.Join(sourcefiles, ", ")
	conf.CreateFromFilenames(path, sourcefiles...)
	//log.Infof("srcfs: %s",srcfs)
	lprog, err := conf.Load()
	if err != nil {
		return nil, errors.Errorf("fail to load config of path: %s and sourcefiles: %s", path, sourcefiles),nil,nil,nil
	}
	prog := ssautil.CreateProgram(lprog, ssa.SanityCheckFunctions)
	checkAst(lprog.Fset,lprog.Created[0].Files[0],lprog.Created[0].Info)

	//os.Exit(0)

	//pkginfo := lprog.Created[0]

	mainPkg := prog.Package(lprog.Created[0].Pkg)


	imports := mainPkg.Pkg.Imports()
	//fmt.Println("main imports:")
	for _,imp := range imports{
		ok := isInternalPkg(imp.Name())
		if !ok {
			Errors.NewErrorMsgOut(Errors.ERR_EXTERNAL_LIB,imp.Path())
			//log.Warningf("this chaincode may introduce an external pkg:%s",imp.Path())
		}
	}



	prog.Build()
	//
	//
	//
	var initf *ssa.Function
	var invokef *ssa.Function
	for _,member := range mainPkg.Members{
		if ty,ok := member.(*ssa.Type); ok{
			t := ty.Type()
			p := types.NewPointer(t)
			initf = prog.LookupMethod(p,mainPkg.Pkg,"Init")
			invokef = prog.LookupMethod(p,mainPkg.Pkg,"Invoke")
			if initf == nil || invokef == nil{
				continue
			}else {
				break
			}
		}
	}
	if initf!= nil{
		log.Debugf("initf:%s \n",initf.Name())
	}

	if initf == nil || invokef == nil{
		log.Fatalf("chaincode file not implement function Init() and Invoke()\n")
	}
	//todo chaincode struct type name
	//s := mainPkg.Type("SimpleAsset")
	//t := s.Type()
	////
	//p := types.NewPointer(t)
	//
	//

	//initf = prog.LookupMethod(p,mainPkg.Pkg,"Init")
	//invokef := prog.LookupMethod(p,mainPkg.Pkg,"Invoke")
	//initf.WriteTo(os.Stdout)
	//
	//fmt.Println("end build ssa pkgs")
	return mainPkg, nil, initf, invokef,prog
	//return nil,nil,nil,nil,nil

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

func isInternalPkg(name string)bool{
	_,ok := internalPkgs[name]
	return ok
}

func initInternalPkg() {
	internalPkgs = make(map[string]struct{})

	internalPkgs["archive"] = struct{}{}
	internalPkgs["bufio"] = struct{}{}
	internalPkgs["builtin"] = struct{}{}
	internalPkgs["bytes"] = struct{}{}
	internalPkgs["cmd"] = struct{}{}
	internalPkgs["compress"] = struct{}{}
	internalPkgs["container"] = struct{}{}
	internalPkgs["context"] = struct{}{}
	internalPkgs["crypto"] = struct{}{}
	internalPkgs["database"] = struct{}{}
	internalPkgs["debug"] = struct{}{}
	internalPkgs["encoding"] = struct{}{}
	internalPkgs["errors"] = struct{}{}
	internalPkgs["expvar"] = struct{}{}
	internalPkgs["flag"] = struct{}{}
	internalPkgs["fmt"] = struct{}{}
	internalPkgs["hash"] = struct{}{}
	internalPkgs["html"] = struct{}{}
	internalPkgs["image"] = struct{}{}
	internalPkgs["index"] = struct{}{}
	internalPkgs["internal"] = struct{}{}
	internalPkgs["io"] = struct{}{}
	internalPkgs["log"] = struct{}{}
	internalPkgs["math"] = struct{}{}
	internalPkgs["mime"] = struct{}{}
	internalPkgs["net"] = struct{}{}
	internalPkgs["os"] = struct{}{}
	internalPkgs["path"] = struct{}{}
	internalPkgs["plugin"] = struct{}{}
	internalPkgs["reflect"] = struct{}{}
	internalPkgs["regexp"] = struct{}{}
	internalPkgs["runtime"] = struct{}{}
	internalPkgs["sort"] = struct{}{}
	internalPkgs["strconv"] = struct{}{}
	internalPkgs["strings"] = struct{}{}
	internalPkgs["sync"] = struct{}{}
	internalPkgs["syscall"] = struct{}{}
	internalPkgs["testing"] = struct{}{}
	internalPkgs["text"] = struct{}{}
	internalPkgs["time"] = struct{}{}
	internalPkgs["unicode"] = struct{}{}
	internalPkgs["unsafe"] = struct{}{}
	internalPkgs["shim"] = struct{}{}
	internalPkgs["peer"] = struct{}{}

}

