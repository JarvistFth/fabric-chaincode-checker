package main

import (
	"chaincode-checker/taint_analysis/checker"
	"chaincode-checker/taint_analysis/logger"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
)

var srcFlagCalled = false
type sourcefiles []string


var log = logger.GetLogger("./debuglogs/test")

func (s *sourcefiles) String() string {
	return fmt.Sprint(*s)
}

func (s *sourcefiles) Set(value string) error {
	srcFlagCalled = true
	for _, file := range strings.Split(value, ",") {
		isGoFile := strings.HasSuffix(file, ".go")
		if !isGoFile {
			errorMessage := file + "is not a .go file"
			return errors.New(errorMessage)
		}
		*s = append(*s, file)
	}
	return nil
}

func main() {
	flag.Usage = func() {
		fmt.Printf("Usage and defaults of %s: \n", os.Args[0])
		fmt.Printf("The flags allpkgs, path and ssf are optional. \n")
		fmt.Printf("The flag sourceFilesFlag is mandatory.\n")
		flag.PrintDefaults()
	}
	var ssf = flag.String("ssf", "./config/sourceandsink.json", "Changes the file which holds the sources and sinks")
	var path = flag.String("path", "chaincode-checker", "The path to the .go-files starting at $GOPATH/src: e.g. the path for $GOPATH/src/example/example.go will be example")
	var sourceFilesFlag sourcefiles
	var allpkgs = flag.Bool("allpkgs", false, "If it is set all packages of the source file will be analyzed, else only the main package.")
	var pkgs = flag.String("pkgs", "", "Specify some packages in addition to the main package which should be analyzed.")
	var ptr = flag.Bool("ptr", true, "If is is set we perfom a pointer analysis, else not")
	flag.Var(&sourceFilesFlag, "src", "comma-seperated list of .go-files which should be analzed")
	flag.Parse()

	if !srcFlagCalled{
		flag.PrintDefaults()
	}else{
		checker.Main(*path,sourceFilesFlag,*ssf,*allpkgs,*pkgs,*ptr)
	}

}