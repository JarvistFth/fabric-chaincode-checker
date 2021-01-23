package utils

import (
	"chaincode-checker/go-taint/taint"
	"encoding/json"
	"fmt"
	"github.com/op/go-logging"
	"io/ioutil"
)

var log = logging.MustGetLogger("main")

const sourcetypeglobal = "global"
const sourcetypefunc = "function"

var SS *SinkAndSources
var SDKfunctions []*SDKFunction
var FunctionConfig *Config

type SinkAndSources struct {
	Sinks []*taint.TaintData
	Sources []*taint.TaintData
}

type Config struct {
	Sources []Source `json:"sources"`
	Sinks []Sink `json:"sinks"`
	SDKFunctions []*SDKFunction `json:"sdk_functions"`
}

type Source struct {
	SourceType string	`json:"source_type"`

	Signature string `json:"signature"`
	Callee string `json:"callee"`
	IsInterface bool `json:"is_interface"`

	Name string `json:"name"`
}

type Sink struct {
	Signature string `json:"signature"`
	Callee string `json:"callee"`
	IsInterface bool	`json:"is_interface"`
}

type SDKFunction struct {
	Signature string `json:"signature"`
	Callee string `json:"callee"`
	IsInterface bool `json:"is_interface"`
}

func ParseSourceAndSinkFile(path string) (*SinkAndSources, error) {
	bytes,err := ioutil.ReadFile(path)
	if err != nil{
		log.Fatalf(err.Error())
		return nil,err
	}

	var sourceAndSinkConfig Config
	SS = &SinkAndSources{
		Sinks:   make([]*taint.TaintData, 0),
		Sources: make([]*taint.TaintData, 0),
	}

	err = json.Unmarshal(bytes,&sourceAndSinkConfig)
	if err != nil{
		log.Fatalf(err.Error())
		return nil,err
	}

	var td *taint.TaintData
	for _,e := range sourceAndSinkConfig.Sources{
		td = taint.NewTaintData(e.Signature,e.Callee,e.Name,e.SourceType == sourcetypeglobal,e.IsInterface)

		SS.Sources = append(SS.Sources,td)
	}

	for _,e := range sourceAndSinkConfig.Sinks{

		td = taint.NewTaintData(e.Signature,e.Callee,"",false,e.IsInterface)
		SS.Sinks = append(SS.Sinks,td)
	}

	SDKfunctions = sourceAndSinkConfig.SDKFunctions
	FunctionConfig = &sourceAndSinkConfig
	log.Debugf("parse source and sink file ending")

	return SS,nil

}

func (ss *SinkAndSources) String() string {
	var ret string
	ret += "\n"
	for _,s := range ss.Sources{
		ret += "sources: "+ s.String()
	}


	for _,s := range ss.Sinks{
		ret += "sinks:" + s.String()
	}
	return ret
}

func (f *SDKFunction) String() string {
	return fmt.Sprintf("sdk function:| signature: %s, callee: %s, interface?:%t\n",f.Signature,f.Callee,f.IsInterface)
}

func (c *Config) SDKFunctionString() string {
	var ret string
	for _,s := range c.SDKFunctions{
		ret += s.String()
	}
	return ret
}