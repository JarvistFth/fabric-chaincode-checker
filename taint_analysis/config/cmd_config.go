package config

//var ValToPtrs map[ssa.Value] pointer.Pointer


var Config *CmdConfig

type CmdConfig struct {
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
	WithPtr bool

}

func NewCmdConfig(path string, sourcefiles []string, sourceAndSinkFile string, allpkgs bool, pkgs string, withptr bool) *CmdConfig {
	cc := &CmdConfig{
		Path:              path,
		SourceFiles:       sourcefiles,
		SourceAndSinkFile: sourceAndSinkFile,
		Allpkgs:           allpkgs,
		Pkgs:              pkgs,
		WithPtr: withptr,
	}
	Config = cc
	return cc
}