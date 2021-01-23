package context

import (
	"chaincode-checker/go-taint/lattice"
	"fmt"
	"golang.org/x/tools/go/ssa"
)

type ValueContextMap struct {
	ctx map[*ValueContextIndent]*ValueContext
}

func NewValueCtxMap() *ValueContextMap {
	return &ValueContextMap{ctx: make(map[*ValueContextIndent]*ValueContext,0)}
}

func (m *ValueContextMap) AddToContext(vc *ValueContext)  {
	m.ctx[vc.ValueIndent] = vc
}

func (m *ValueContextMap) FindInContext(callee *ssa.Function, latEntry lattice.Lattice) *ValueContext {
	vcindent := &ValueContextIndent{
		In:       latEntry,
		Function: callee,
	}
	var ret *ValueContext
	for k,v := range m.ctx{
		if k.Equal(vcindent){
			ret = v
		}
	}
	//ret := m.ctx[vcindent]

	if ret == nil{
		return nil
	}
	return ret
}

func (m *ValueContextMap) Len() int {
	return len(m.ctx)
}

func (m *ValueContextMap) IsCtxExist(vci *ValueContextIndent) (bool, *ValueContext) {
	ctx := m.ctx[vci]
	if ctx == nil{
		return false,nil
	}
	return true,ctx
}

// 1) is the potential value context in the map
// 2) are the in values equal

func (m *ValueContextMap) Known(vc *ValueContext, params []ssa.Value) (bool, *ValueContext) {
	ctx := m.ctx[vc.ValueIndent]
	if ctx == nil{
		return false,nil
	}

	entryEq := ctx.IsEntryEqual(vc,params)

	return entryEq,ctx
}

func (m *ValueContextMap) String() string {

	var s string

	for _,v := range m.ctx{
		s += fmt.Sprintf(" %s \n",v.String())
	}
	return s
}

