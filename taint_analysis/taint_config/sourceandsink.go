package taint_config

import (
	"chaincode-checker/taint_analysis/logger"
	"encoding/json"
	"io/ioutil"
)

var SSConfig *Config
var log = logger.GetLogger("./debuglogs/test")

type Config struct {
	Sources []Source            `json:"sources"`
	Sinks []Sink                `json:"sinks"`
	SDKFunctions []*SDKFunction `json:"sdk_functions"`
	WarningFunctions []*WarningFunction `json:"warning_functions"`
	ReadWriteFunctions []*ReadWriteFunction `json:"readwrite_functions"`
}

type Source struct {
	Signature string `json:"signature"`
	Callee string `json:"callee"`
	IsInterface bool `json:"is_interface"`
	Type	string `json:"type"`
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

type WarningFunction struct {
	Signature string `json:"signature"`
	Callee string `json:"callee"`
	IsInterface bool `json:"is_interface"`
	Type	string `json:"type"`
}

type ReadWriteFunction struct {
	Signature string `json:"signature"`
	Callee string `json:"callee"`
	IsInterface bool `json:"is_interface"`
	Type	string `json:"type"`
}

func NewSinkAndSourceCfgFromFile(path string) (*Config,error) {
	bytes,err := ioutil.ReadFile(path)
	if err != nil{
		log.Fatalf("get sources and sink cfg files error: %s",err.Error())
	}

	var config Config

	err = json.Unmarshal(bytes,&config)

	if err != nil{
		log.Fatalf("unmarshal json file error: %s",err.Error())
		return nil,nil
	}
	SSConfig = &config
	log.Debug(config.String())
	return SSConfig,nil
}

func (c *Config) String() string {
	var ret string
	for _,s := range c.Sources{
		ret += "sources:" + s.Callee + " " + s.Signature + "\n"
	}

	for _,s := range c.Sinks{
		ret += "sinks:" + s.Callee + " " + s.Signature + "\n"
	}

	for _,s := range c.SDKFunctions{
		ret += "sdk functions:" + s.Callee + " " + s.Signature + "\n"
	}

	for _,s := range c.WarningFunctions{
		ret += "warning functions:" + s.Callee + " " + s.Signature + "\n"
	}

	for _,s := range c.ReadWriteFunctions{
		ret += "ReadWriteFunctions:" + s.Callee + " " + s.Signature + "\n"
	}
	return ret


}

