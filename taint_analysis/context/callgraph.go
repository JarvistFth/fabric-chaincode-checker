package context

import (
	"chaincode-checker/taint_analysis/latticer"
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

	LatticeTable LatticeMap
}


func GetCallGraph(callee string, method *ssa.Function, args []ssa.Value) *CallGraph {


	id := genid(method)
	if callgraph,ok := CallGraphs.Get(id); ok{
		return callgraph.(*CallGraph)
	}
	c := &CallGraph{
		id:     id,
		callee: callee,
		caller: method.Name(),
		method: method,
		args:   args,
		argLattice: make(latticer.Lattices,0),
		retLattice: make([]latticer.Lattice,0),
		instrs: NewTaskList(),
		LatticeTable: make(LatticeMap),
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


//here ssa.function.params are the called function args.. inLattice means the actual arg's lattice
func GetFunctionContext(ssaFunc *ssa.Function,isClosure, isPtr bool, inLattice latticer.Lattices) (*CallGraph,error) {
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

	fc := GetCallGraph(ssaFunc.Name(),ssaFunc,args)

	log.Debugf("ssafunc:%s ,argslen:",len(args))
	//1. get args
	//2. table args -> init
	argLattice := make(latticer.Lattices,len(args))
	if len(args) != 0  {
		fc.initParamsLattice(args,argLattice)
		for i:=0 ;i<len(argLattice);i++{
			argLattice[i].LeastUpperBound(inLattice[i])
		}
	}
	fc.SetArgLattice(argLattice)

	//TODO :same function may need not analyze instruction again?
	fc.analyzeInstructions(ssaFunc,isPtr)
	return fc,nil


}




func(c *CallGraph) initParamsLattice(args []ssa.Value, argLattice latticer.Lattices) {

	for i,arg := range args{
		argLattice[i] = c.LatticeTable.GetLattice(arg)
	}


}

func (c *CallGraph) Id() string {
	return c.id
}

func genid(method *ssa.Function) string {
	//pos := method.Pos()
	//location := method.Prog.Fset.File(pos).Line(pos)
	return fmt.Sprintf("%s.%s:%d",method.Pkg.Pkg.Name(),method.Name())
}
