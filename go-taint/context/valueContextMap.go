package context

import (
	"chaincode-checker/go-taint/lattice"
	"fmt"
	"golang.org/x/tools/go/ssa"
)

type ValueContextMap map[*ValueContextIndent]*ValueContext

func NewValueCtxMap() ValueContextMap {
	return make(map[*ValueContextIndent]*ValueContext,0)
}

func (m ValueContextMap) AddToContext(vc *ValueContext)  {
	m[vc.ValueIndent] = vc
}

func (m ValueContextMap) FindInContext(callee *ssa.Function, latEntry lattice.Lattice) *ValueContext {
	vcindent := &ValueContextIndent{
		In:       latEntry,
		Function: callee,
	}

	ret := m[vcindent]

	if ret == nil{
		return nil
	}
	return ret
}

func (m ValueContextMap) Len() int {
	return len(m)
}

func (m ValueContextMap) IsCtxExist(vc *ValueContextIndent) (bool, *ValueContext) {
	ctx := m[vc]
	if ctx == nil{
		return false,nil
	}
	return true,ctx
}

func (m ValueContextMap) String() string {

	var s string

	for _,v := range m{
		s += fmt.Sprintf(" %s \n",v.String())
	}
	return s
}