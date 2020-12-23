package utils

import (
	"chaincode-checker/go-taint/taint"
	"encoding/json"
	"io/ioutil"
	"log"
)

var Sinks = make([]*taint.TaintData,0)
var Sources = make([]*taint.TaintData,0)

const sourcetypeglobal = "global"
const sourcetypefunc = "function"

type Config struct {
	Sources []Source `json:"sources"`
	Sinks []Sink `json:"sinks"`
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

func ParseSourceAndSinkFile(path string) error {
	bytes,err := ioutil.ReadFile(path)
	if err != nil{
		log.Fatalf(err.Error())
		return err
	}

	var sourceAndSinkConfig Config

	err = json.Unmarshal(bytes,&sourceAndSinkConfig)
	if err != nil{
		log.Fatal(err.Error())
		return err
	}

	var td *taint.TaintData
	for _,e := range sourceAndSinkConfig.Sources{

		td = &taint.TaintData{
			Sig:         e.Signature,
			Callee:      e.Callee,
			IsGlobal:    e.SourceType == sourcetypeglobal,
			IsInterface: e.IsInterface,
			Name:        e.Name,
		}

		Sources = append(Sources,td)
	}

	for _,e := range sourceAndSinkConfig.Sinks{
		td = &taint.TaintData{
			Sig:         e.Signature,
			Callee:      e.Callee,
			IsGlobal:    false,
			IsInterface: e.IsInterface,
			Name:        "",
		}
		Sinks = append(Sinks,td)
	}

	log.Printf("end")
	return nil

}