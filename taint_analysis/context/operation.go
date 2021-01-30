package context

import (
	"chaincode-checker/taint_analysis/ssautils"
	"golang.org/x/tools/go/ssa"
)

func Flow(ctx InstructionContext) {
	switch instr := ctx.instruction.(type){
	case ssa.Value, *ssautils.Send, *ssa.Store, *ssa.Go, *ssa.Defer:
		//flow

		break
	case *ssa.Jump:
		//jump
		break
	case *ssa.Return:
		//return
		break
	case ssa.CallInstruction, *ssa.Call, *ssa.MakeClosure:
		//
		break

	case *ssa.Phi:
	case *ssa.Next:
	case *ssa.If:
		instr.Block().Dominees()

		

		



	}
}
