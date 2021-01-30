package checker

import (
	"chaincode-checker/taint_analysis/project_config"
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
	_, _ = taint_config.NewSinkAndSourceCfgFromFile(Config.SourceAndSinkFile)
}

func BuildSSA() *ssa.Package {
	mainpkg,err,initfn,invokefn,prog := ssautils.Build(Config.Path,Config.SourceFiles)
	if err != nil{
		log.Fatalf("error when build ssa...")
		return nil
	}

	mainpkg.Build()
	project_config.WorkingProject = project_config.GetProject(invokefn,initfn)
	invokefn.WriteTo(os.Stdout)
	project_config.WorkingProject.Program = prog
	return mainpkg
}

func setPkgsList(mainpkg *ssa.Package)  {
	if Config.Allpkgs{
		project_config.WorkingProject.Setpkgs(project_config.WorkingProject.InvokeFunc.Prog.AllPackages())
	}else{
		log.Infof("only analyze main pkgs")
		project_config.WorkingProject.Packages = []*ssa.Package{mainpkg}
		if Config.Pkgs != ""{
			pkgs := make([]*ssa.Package,0)
			for _,pkg := range strings.Split(Config.Pkgs,","){
				p := project_config.WorkingProject.InvokeFunc.Prog.ImportedPackage(pkg)
				if p != nil{
					pkgs = append(pkgs,p)
				}else{
					//log.Infof("pkg: [%s] is unknown in %s",pkg,ck.MainFunc.String())
					utils.HandleError(errors.New(fmt.Sprintf("pkg: [%s] is unknown in %s",pkg, project_config.WorkingProject.InvokeFunc.String())),"")
				}
			}
			project_config.WorkingProject.Setpkgs(pkgs)
		}
	}
}

func setupPtrs(mains []*ssa.Package) {
	project_config.WorkingProject.SetPtrConfig(mains)
	project_config.WorkingProject.SetPtrResult()
	project_config.WorkingProject.SetValToPtrs()
}



