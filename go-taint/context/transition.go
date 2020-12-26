package context

import (
	"fmt"
	"golang.org/x/tools/go/ssa"
)

type Transitions struct {
	context       *ValueContext
	targetContext *ValueContext
	node          ssa.Instruction
}

func (t1 *Transitions) Equal(t2 *Transitions) bool {
	equalContext := t1.context.Equal(t2.context)
	equalTargetContext := t1.targetContext.Equal(t2.targetContext)
	equalnode := t1.node == t2.node
	return equalContext && equalTargetContext && equalnode

}

func NewTransition(start *ValueContext, targetContext *ValueContext, node ssa.Instruction) *Transitions{
	if start == nil || targetContext == nil || node == nil{
		return nil
	}

	ret := &Transitions{
		context:       start,
		targetContext: targetContext,
		node:          node,
	}
	return ret
}

func (t1 *Transitions) GetNode() ssa.Instruction {
	return t1.node
}

func (t1 *Transitions) GetTargetContext() *ValueContext {
	return t1.targetContext
}

func (t1 *Transitions) GetStartContext() *ValueContext {
	return t1.targetContext
}

func (t1 *Transitions) String() string {
	return fmt.Sprintf("startContext: %s,\n node: %s, \n | targetContext: %s",t1.context.String(), t1.node.String(),t1.targetContext.String())
}
