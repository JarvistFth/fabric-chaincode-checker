package context

import (
	"chaincode-checker/taint_analysis/latticer"
	"chaincode-checker/taint_analysis/project_config"
	"chaincode-checker/taint_analysis/utils"
	"fmt"
	"github.com/pkg/errors"
	"golang.org/x/tools/go/ssa"
)

var idcnt = 0

type FunctionContext struct {
	id int

	funcName string

	method *ssa.Function

	args []ssa.Value

	argLattice []latticer.Lattice

	retLattice []latticer.Lattice
}

func NewFunctionContext(method *ssa.Function, args []ssa.Value, argLattice []latticer.Lattice) *FunctionContext {
	c := &FunctionContext{
		id:         idcnt,
		funcName:   method.Name(),
		method:     method,
		args:       args,
		//argLattice: make([]latticer.Lattice,0),
		argLattice: argLattice,
		retLattice: make([]latticer.Lattice,0),
	}
	idcnt++
	return c
}

func (c *FunctionContext) GetArgs() []ssa.Value {
	return c.args
}

func (c *FunctionContext) GetMethod() *ssa.Function {
	return c.method
}

func (c *FunctionContext) GetName() string {
	return c.funcName
}

func (c *FunctionContext) GetInLattice() []latticer.Lattice {
	return c.argLattice
}

func (c *FunctionContext) GetReturnLattice() []latticer.Lattice {
	return c.retLattice
}

func (c *FunctionContext) String() string {
	var ret string
	ret += fmt.Sprintf("call function:%s\n",c.funcName)

	ret += "arg latticer:\n"
	for _, latarg := range c.argLattice {
		ret += latarg.String()
	}

	ret += "return latticer"
	for _, retval := range c.retLattice{
		ret += retval.String()
	}
	return ret
}

func (c *FunctionContext) SetReturnLattice(retLattices []latticer.Lattice) {
	c.retLattice = retLattices
}

func (c *FunctionContext) SetArgLattice(argLattices []latticer.Lattice) {
	c.argLattice = argLattices
}

func GetFunctionContext(ssaFunc *ssa.Function,isClosure, isPtr bool) (*FunctionContext,error) {
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


	fc := NewFunctionContext(ssaFunc,args,argLattice)



	return fc,nil


}


func getLatticeFromParams(args []ssa.Value, isPtr bool) latticer.Lattices {
	var ret latticer.Lattices

	for _,arg := range args{
		var lat latticer.Lattice
		if isPtr {
			lat = latticer.NewLatticePointer(utils.GenKeyFromSSAValue(arg),arg,project_config.WorkingProject.ValToPtrs)
		}else{
			lat = latticer.NewLatticeValue(utils.GenKeyFromSSAValue(arg),arg)
		}
		ret = append(ret,lat)
	}

	return ret

}



