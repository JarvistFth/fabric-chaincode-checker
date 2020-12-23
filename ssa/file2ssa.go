package ssa

import (
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
	"log"
)

func SSAfromFile(path string)  {
	//var conf loader.Config
	//conf.CreateFromFilenames(path,sourcesfileString)
	//programConfig,err := conf.Load()

	config := packages.Config{Dir: path, Mode: packages.LoadAllSyntax}
	initial,err := packages.Load(&config)
	if err != nil{
		log.Fatalf(err.Error())
	}
	program,_ := ssautil.AllPackages(initial,ssa.PrintPackages)
	program.Build()

	//for k,v := range program.Package()
	log.Printf("build end")
	//mainProgram := program.Package(types.NewPackage(path,"main"))
	//log.Printf("main pkg: %s",mainProgram.String())

}
