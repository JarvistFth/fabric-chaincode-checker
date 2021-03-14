package checker

import (
	"chaincode-checker/taint_analysis/config"
	"chaincode-checker/taint_analysis/ssautils"
	"chaincode-checker/taint_analysis/taint_config"
	"chaincode-checker/taint_analysis/utils"
	"errors"
	"fmt"
	"github.com/op/go-logging"
	"golang.org/x/tools/go/ssa"
	"os"
	"strings"
)
var log = logging.MustGetLogger("main")

func InitSSConfig() {
	_, _ = taint_config.NewSinkAndSourceCfgFromFile(config.Config.SourceAndSinkFile)
}

func BuildSSA() *ssa.Package {
	mainpkg,err,initfn,invokefn,prog := ssautils.Build(config.Config.Path,config.Config.SourceFiles)
	if err != nil{
		log.Fatalf("error when build ssa...")
		return nil
	}

	mainpkg.Build()
	config.WorkingProject = config.GetProject(invokefn,initfn)
	invokefn.WriteTo(os.Stdout)
	config.WorkingProject.Program = prog
	return mainpkg
}

func setPkgsList(mainpkg *ssa.Package)  {
	if config.Config.Allpkgs{
		config.WorkingProject.Setpkgs(config.WorkingProject.InvokeFunc.Prog.AllPackages())
	}else{
		log.Infof("only analyze main pkgs")
		config.WorkingProject.Packages = []*ssa.Package{mainpkg}
		if config.Config.Pkgs != ""{
			pkgs := make([]*ssa.Package,0)
			for _,pkg := range strings.Split(config.Config.Pkgs,","){
				p := config.WorkingProject.InvokeFunc.Prog.ImportedPackage(pkg)
				if p != nil{
					pkgs = append(pkgs,p)
				}else{
					//log.Infof("pkg: [%s] is unknown in %s",pkg,ck.MainFunc.String())
					utils.HandleError(errors.New(fmt.Sprintf("pkg: [%s] is unknown in %s",pkg, config.WorkingProject.InvokeFunc.String())),"")
				}
			}
			config.WorkingProject.Setpkgs(pkgs)
		}
	}
}

func SetupPtrs(mains []*ssa.Package) {
	config.WorkingProject.SetPtrConfig(mains)
	config.WorkingProject.SetPtrResult()
	config.WorkingProject.SetValToPtrs()
}



