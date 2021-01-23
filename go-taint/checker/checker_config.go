package checker

import (
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
)

var ValToPtrs map[ssa.Value] pointer.Pointer



type CheckerConfig struct {
	//The path to the .go-files starting at $GOPATH/src
	Path              string
	//list of .go-files which should be analyzed
	SourceFiles       []string
	//the file which holds the sources and sinks
	SourceAndSinkFile string
	//analyze all pkgs?
	Allpkgs           bool
	//Specify some packages in addition to the main package which should be analyzed
	Pkgs              string
	//If is is set we perform a pointer analysis, else not
	IsPtr             bool
}

func NewCheckerConfig(path string, sourcefiles []string, sourceAndSinkFile string, allpkgs bool, pkgs string, ptr bool) *CheckerConfig {
	cc := &CheckerConfig{
		Path:              path,
		SourceFiles:       sourcefiles,
		SourceAndSinkFile: sourceAndSinkFile,
		Allpkgs:           allpkgs,
		Pkgs:              pkgs,
		IsPtr:             ptr,
	}
	return cc
}