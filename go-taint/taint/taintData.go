package taint

import "fmt"

type TaintData struct {
	sig    string
	callee string

	isGlobal    bool
	isInterface bool
	name        string
}

func NewTaintData(sig,callee,name string, isglobal,isinterface bool) *TaintData {
	td := &TaintData{
		sig:         sig,
		callee:      callee,
		isGlobal:    isglobal,
		isInterface: isinterface,
		name:        name,
	}
	return td
}

func (d *TaintData) IsInterface() bool {
	return d.isInterface
}

func (d *TaintData) IsGlobal() bool {
	return d.isGlobal
}

func (d *TaintData) GetSignature() string {
	return d.sig
}

func (d *TaintData) GetCallee() string {
	return d.callee
}

func (d *TaintData) GetName() string {
	return d.name
}

func (d *TaintData) String() string {
	return fmt.Sprintf("sig: %s, callee: %s, name: %s, global: %t, interface: %t\n",d.sig,d.callee,d.name,d.isGlobal,d.isInterface)
}
