package context

import (
	"chaincode-checker/taint_analysis/latticer"
	"chaincode-checker/taint_analysis/config"
	"chaincode-checker/taint_analysis/utils"
	"fmt"
	"github.com/emirpasic/gods/maps/hashmap"
	"github.com/pkg/errors"
	"golang.org/x/tools/go/ssa"
)

var CallGraphs *hashmap.Map

type CallGraph struct {
	id string

	callee string

	caller string

	method *ssa.Function

	args []ssa.Value

	argLattice []latticer.Lattice

	retLattice []latticer.Lattice

	instrs *TaskList
}


func GetCallGraph(callee string, method *ssa.Function, args []ssa.Value, argLattice []latticer.Lattice) *CallGraph {
	if CallGraphs == nil{
		CallGraphs = hashmap.New()
	}


	id := genid(method.Pkg.String(),method.Name())
	if callgraph,ok := CallGraphs.Get(id); ok{
		return callgraph.(*CallGraph)
	}
	c := &CallGraph{
		id:     id,
		callee: callee,
		caller: method.Name(),
		method: method,
		args:   args,
		//argLattice: make([]latticer.Lattice,0),
		argLattice: argLattice,
		retLattice: make([]latticer.Lattice,0),
		instrs: NewTaskList(),
	}

	CallGraphs.Put(id,c)
	return c
}

func (c *CallGraph) GetArgs() []ssa.Value {
	return c.args
}

func (c *CallGraph) GetMethod() *ssa.Function {
	return c.method
}

func (c *CallGraph) GetName() string {
	return c.caller
}

func (c *CallGraph) GetInLattice() []latticer.Lattice {
	return c.argLattice
}

func (c *CallGraph) GetReturnLattice() []latticer.Lattice {
	return c.retLattice
}

func (c *CallGraph) String() string {
	var ret string
	ret += fmt.Sprintf("call function:%s\n",c.caller)

	ret += "arg latticer:\n"
	for _, latarg := range c.argLattice {
		ret += latarg.String()
	}

	ret += "\nreturn latticer"
	for _, retval := range c.retLattice{
		ret += retval.String()
	}
	return ret
}

func (c *CallGraph) SetReturnLattice(retLattices []latticer.Lattice) {
	c.retLattice = retLattices
}

func (c *CallGraph) SetArgLattice(argLattices []latticer.Lattice) {
	c.argLattice = argLattices
}

func GetFunctionContext(ssaFunc *ssa.Function,isClosure, isPtr bool) (*CallGraph,error) {
	if ssaFunc == nil{
		return nil,errors.New("error, function is nil with context")
	}
	var args []ssa.Value
	if isClosure{
		fs := ssaFunc.FreeVars
		args = make([]ssa.Value,len(fs))
		for i,f := range args{
			args[i] = f
		}
	}else{
		ps := ssaFunc.Params
		args = make([]ssa.Value,len(ps))
		for i,p := range ps{
			args[i] = p
		}
	}
	argLattice := getLatticeFromParams(args,isPtr)


	fc := GetCallGraph(ssaFunc.Name(),ssaFunc,args,argLattice)
	fc.analyzeInstructions(ssaFunc,isPtr)

	return fc,nil


}

func genid(pkgname, funcname string) string{
	return pkgname+"."+funcname
}


func getLatticeFromParams(args []ssa.Value, isPtr bool) latticer.Lattices {
	var ret latticer.Lattices

	for _,arg := range args{
		var lat latticer.Lattice
		if isPtr {
			lat = latticer.NewLatticePointer(utils.GenKeyFromSSAValue(arg),arg, config.WorkingProject.ValToPtrs)
		}else{
			lat = latticer.NewLatticeValue(utils.GenKeyFromSSAValue(arg),arg)
		}
		ret = append(ret,lat)
	}

	return ret

}

func (c *CallGraph) Id() string {
	return c.id
}
