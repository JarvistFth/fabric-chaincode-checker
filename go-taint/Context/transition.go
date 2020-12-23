package Context

import "golang.org/x/tools/go/ssa"

type Transitions struct {
	context       *ValueContext
	targetContext *ValueContext
	node          ssa.Instruction
}
