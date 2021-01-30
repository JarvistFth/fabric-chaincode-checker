package context

import (
	"chaincode-checker/taint_analysis/latticer"
	"chaincode-checker/taint_analysis/project_config"
	"chaincode-checker/taint_analysis/utils"
	"fmt"
	"github.com/op/go-logging"
	"golang.org/x/tools/go/ssa"
)
var log = logging.MustGetLogger("Main")

type InstructionContext struct {

	name string
	functionContext *FunctionContext
	instruction ssa.Instruction

	latticeIn  latticer.Lattices
	latticeOut latticer.Lattice
}

func NewInstructionContext(vc *FunctionContext, instr ssa.Instruction, isPtr bool) *InstructionContext {
	var out latticer.Lattice
	if val,ok := instr.(ssa.Value);ok{
		if isPtr{
			out = latticer.NewLatticePointer(utils.GenKeyFromSSAValue(val),val,project_config.WorkingProject.ValToPtrs)
		}else{
			out = latticer.NewLatticeValue(utils.GenKeyFromSSAValue(val),val)
		}
	}

	ret := &InstructionContext{
		name:            instr.String(),
		functionContext: vc,
		instruction:     instr,
		latticeIn:       make(latticer.Lattices,0),
		latticeOut:      out,
	}
	return ret
}

func (c *InstructionContext) GetInstr() ssa.Instruction {
	return c.instruction
}

func (c *InstructionContext) Name() string {
	return c.name
}

func (c *InstructionContext) SetLatticeIn(l []latticer.Lattice) {
	c.latticeIn = l
}

func (c InstructionContext) SetLatticeOut(l latticer.Lattice) {
	c.latticeOut = l
}

func (c *InstructionContext) AppendLatticeIn(l... latticer.Lattice) {
	c.latticeIn = append(c.latticeIn,l...)
}

func (c *InstructionContext) GetLatticeIn() latticer.Lattices {
	return c.latticeIn
}

func (c *InstructionContext) GetLatticeOut() latticer.Lattice {
	return c.latticeOut
}

func (c *InstructionContext) String() string {
	var str string
	for _,s := range c.latticeIn{
		str += s.String()
	}

	if _,ok := c.instruction.(ssa.Value);ok{
		return fmt.Sprintf("name:%s, function:%s\n latticein:%s latticeOut:%s",c.name,c.functionContext.GetName(),str,c.latticeOut.String())
	}else{
		return fmt.Sprintf("name:%s, function:%s\n latticein:%s latticeOut: no out lattice",c.name,c.functionContext.GetName(),str)
	}
}

func (c *InstructionContext) IsValue() bool {
	_,ok := c.instruction.(ssa.Value)
	return ok
}

func (c InstructionContext) IsCall() bool {
	_,ok := c.instruction.(ssa.CallInstruction)
	return ok
}