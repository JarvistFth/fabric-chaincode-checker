package checker

import (
	"chaincode-checker/taint_analysis/config"
	"chaincode-checker/taint_analysis/logger"
	"chaincode-checker/taint_analysis/ssautils"
	"chaincode-checker/taint_analysis/taint_config"
	"chaincode-checker/taint_analysis/utils"
	"errors"
	"fmt"
	"go/types"
	"golang.org/x/tools/go/ssa"
	"strings"
)

func InitSSConfig() {
	_, _ = taint_config.NewSinkAndSourceCfgFromFile(config.Config.SourceAndSinkFile)
}

func BuildSSA() *ssa.Package {
	mainpkg,err,initfn,invokefn,prog := ssautils.Build(config.Config.Path,config.Config.SourceFiles)
	//ssautils.Build(config.Config.Path,config.Config.SourceFiles)
	if err != nil{
		log.Fatalf("error when build ssa...")
		return nil
	}
	config.MainPkg = mainpkg
	mainpkg.Build()
	config.NewProjecet(prog,initfn,invokefn)
	invokefn.WriteTo(logger.LogFile)
	return mainpkg
	//return nil
}

func setPkgsList(mainpkg *ssa.Package)  {
	if config.Config.Allpkgs{
		config.SetPkgs(config.InvokeFunc.Prog.AllPackages())
	}else{
		log.Infof("only analyze main pkgs")
		config.Packages = []*ssa.Package{mainpkg}
		if config.Config.Pkgs != ""{
			pkgs := make([]*ssa.Package,0)
			for _,pkg := range strings.Split(config.Config.Pkgs,","){
				p := config.InvokeFunc.Prog.ImportedPackage(pkg)
				if p != nil{
					pkgs = append(pkgs,p)
				}else{
					//log.Infof("pkg: [%s] is unknown in %s",pkg,ck.MainFunc.String())
					utils.HandleError(errors.New(fmt.Sprintf("pkg: [%s] is unknown in %s",pkg, config.InvokeFunc.String())),"")
				}
			}
			config.SetPkgs(pkgs)
		}
	}
}

func SetupPtrs(mains *ssa.Package) {
	imps := []*ssa.Package{mains}
	//imp := mains.Pkg.Imports()
	//for _, p := range imp{
	//	ssap := mains.Prog.Package(p)
	//	imps = append(imps,ssap)
	//}
	cfg := config.GetPtrCfg(config.InvokeFunc,imps...)
	config.PtrCfg = cfg
	mems := mains.Members
	for _,mem := range mems{
		if t,ok := mem.(*ssa.Type); ok{
			p := types.NewPointer(t.Type())
			ms := mains.Prog.MethodSets.MethodSet(p)
			for i:=0; i<ms.Len(); i++{
				sel := ms.At(i)
				if sel.Kind() == types.MethodVal{
					fn := mains.Prog.MethodValue(sel)
					log.Debugf("types.function name:%s",fn.Name())
					config.AddQueryInFunction(cfg,fn)
				}
			}
			ms = mains.Prog.MethodSets.MethodSet(t.Type())
			for i:=0; i<ms.Len(); i++{
				sel := ms.At(i)
				if sel.Kind() == types.MethodVal{
					fn := mains.Prog.MethodValue(sel)
					log.Debugf("types.function name:%s",fn.Name())
					config.AddQueryInFunction(cfg,fn)
				}
			}
		}
	}
	config.UpdatePtrResultAndMap(cfg,config.InvokeFunc)
}



