package main

import (
	"chaincode-checker/go-taint/checker"
	"chaincode-checker/go-taint/lattice"
	"chaincode-checker/go-taint/logger"
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
		ck := checker.NewChecker(*path,sourceFilesFlag,*ssf,*allpkgs,*pkgs,*ptr)
		logger.SetLogger("./debuglogs/test")
		//ck.SetLogger("./debuglogs/test")
		ck.Init()
		err := ck.StartAnalyzing()

		if err != nil {
			switch err := err.(type) {
			case *lattice.ErrInFlows:
				fmt.Printf("err.NumberOfFlows: %d, messages are: \n", err.NumberOfFlows())
				fmt.Printf("%s\n", err.Error())
			default:
				log.Errorf("Errors: %+v\n", err)
				os.Exit(1)
			}
		} else {
			fmt.Printf("Gongrats. Gotcha has not found an error.\n")
			fmt.Printf("Your parameters are: \n")
			fmt.Printf("path: %s\n", *path)
			fmt.Printf("source file: %s\n", sourceFilesFlag)
			fmt.Printf("sources and sinks file: %s\n", *ssf)
			os.Exit(0)
		}

	}

}


//func setlogger(){
//	logfile,_ = os.OpenFile("./debuglogs/test.txt",os.O_CREATE|os.O_WRONLY|os.O_APPEND,0666)
//	log.SetOutput(logfile)
//	log.SetFlags(log.Lshortfile)
//}
