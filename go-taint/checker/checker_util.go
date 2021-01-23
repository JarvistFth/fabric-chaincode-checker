package checker

import (
	"chaincode-checker/go-taint/context"
	"github.com/pkg/errors"
	"golang.org/x/tools/go/ssa"
)

func(ck *Checker) handleReturn(c *context.InstructionContext) {
	c.GetValueContext().NewExitValue(c.GetOut())

	anotherccs := ck.ctxTransToAnotherX(c)

	for _,d := range anotherccs{
		log.Debugf("d %s\n", d.String())
		ck.taskList.Add(d)
	}

}

func(ck *Checker) checkAndHandleReturn(c *context.InstructionContext) {
	isRet := ck.checkReturn(c)
	if isRet {
		ck.handleReturn(c)
	}
}

// checkReturn returns true if c's node is a *ssa.Return statement.
func(ck *Checker) checkReturn(c *context.InstructionContext) bool {
	_, ok := c.GetNode().(*ssa.Return)
	return ok
}

func (ck *Checker) checkAndHandleChange(c *context.InstructionContext) error {
	unchanged,err := c.GetIn().Equal(c.GetOut())
	//true is changed, false means unchanged

	if err != nil{
		return errors.Wrapf(err,"equal failed with context.in: %s, context.out %s",c.GetIn().String(),c.GetOut().String())
	}

	if unchanged{
		return err
	}else{
		//changed , handle it
		log.Debugf("checkAndHandleChange: lattice have changed, add successor")
		ck.AddSuccessor(c)
		return nil
	}

}