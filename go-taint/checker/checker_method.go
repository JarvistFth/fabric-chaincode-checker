package checker

import (
	"chaincode-checker/go-taint/context"
	"chaincode-checker/go-taint/lattice"
	"chaincode-checker/go-taint/ssautils"
	"github.com/pkg/errors"
	"golang.org/x/tools/go/ssa"
)



func (ck *Checker) updateNewContext(vc *context.ValueContext, ps []ssa.Value, c *context.InstructionContext, callee *ssa.Function, call ssa.Instruction)  {
	vcInCtxMap,knownCtx := ck.ValueCtxMap.Known(vc,ps)

	callerCtx := c.GetValueContext()
	if knownCtx == nil{
		knownCtx = vc
	}
	calleeCtx := knownCtx

	ck.NewTransitions(callerCtx,calleeCtx,call)

	if vcInCtxMap{
		b1 := matchRetStatements(calleeCtx.GetExitValue(),callerCtx.GetExitValue(),calleeCtx.GetMethod(),call)
		b2 := c.GetOut()

		lup,err := b1.LeastUpperBound(b2)
		if err != nil{
			errors.Wrap(err,"")
		}
		vc.RetValueLattice = lup
		c.SetOut(lup)
	}
}




func (ck *Checker)Flow(c *context.InstructionContext) error {
	// Check, whether c.in implements the Semanticer interface.
	// (Else a flow is not possible because methods are missing.)

	//log.Debugf("callsite :%s\n",c.String())
	lIn, ok := c.GetIn().(lattice.SemanticeInterface)
	if !ok {
		log.Fatalf("%v throws an error because it doesn't implement the interface transferFunction.Semanticer", c.GetIn())
	}

	var ff lattice.PlainFF
	// Flow the node [a normal as well as a call node]
	// The flow function can also handle on not ssa.Values, but the lattice needs a ssa.Value
	switch n := c.GetNode().(type) {
	case ssa.Value, *ssautils.Send, *ssa.Store, *ssa.Go, *ssa.Defer:
		// Get the flow function for n upon the lattice and handle the case that ff = nil
		ff = lIn.TransferFunction(n, ck.pointerResult)
		if ff == nil {
			em := "the returned flow function is nil. Called upon Lattice: % \n  with node: %s and pta %v\n"
			log.Fatalf(em, lIn, c.GetNode().String(), ck.pointerResult)
			//return errors.Errorf(em, lIn, c.GetNode().String(), ck.pointerResult)
		}

		// Get the correct value for the flow function (for Send and ssa.Store the ssa.Value is within the type)
		// and the value which should be changed through the flow.
		// In the case of a *Send the out value is the channel.
		var valin, valout ssa.Value
		switch n := n.(type) {
		case ssa.Value:
			valin = n
			valout = n
		case *ssautils.Send:
			valin = n.X
			valout = n.Chan
		case *ssa.Store:
			valin = n.Val
			valout = n.Val
		case *ssa.Go:
			valin = n.Common().Value
			valout = n.Common().Value
		case *ssa.Defer:
			valin = n.Common().Value
			valout = n.Common().Value

		}

		valn := c.GetIn().GetTag(valin)

		// Flow the flow function and handle the errors
		ffval, err := ff(valn)
		if err != nil {
			switch err := err.(type) {
			case *lattice.ErrLeak:
				log.Debugf("add errleak")
				ck.ErrFlows.Add(err)
			default:
				return errors.Wrapf(err, "failed call ff with %s, %s", valn.String(),err.Error())
			}
			err = nil
		}

		// Build the lup of the current value which should be set and the value from the flow function
		lupval := ffval.LeastUpperBound(c.GetIn().GetTag(valout))
		// Set the out lattice for the value
		c.SetOut(c.GetIn())
		_ = c.GetOut().SetTag(valout, lupval)
	case *ssa.Jump, *ssa.Return:
		// ToDo improve - current problem: can't pass n as value for the lattice (is *ssa.Instruction)
		c.SetOut(c.GetIn())
	case *ssa.If:

		//TODO HANDLE IF STATEMENT

		//b := n.Block().Instrs
		//for _,i := range b{
		//	log.Debugf("if statement block: %s",i.String())
		//}
		//p := n.Block().Preds
		//for _, i := range p{
		//	log.Debugf(i.String())
		//}
		//p = n.Block().Succs
		//for _, i := range p{
		//	log.Debugf(i.String())
		//}
		//ck.AddSuccessor(n)
	}

	// Get information whether the node is a call or a closure
	// Line 23
	//log.Printf("callsite - 1  :%s\n",c.String())

	switch call := c.GetNode().(type) {

	// handle in next case
	case ssa.CallInstruction, *ssa.MakeClosure, *ssa.Call:
		var staticCallee *ssa.Function
		var paramsCaller []ssa.Value
		var vc *context.ValueContext
		switch call := call.(type) {
		case ssa.CallInstruction:
			// Get the static callee of the node
			// Line 24 - 26
			var callCom *ssa.CallCommon
			callCom = call.Common()
			staticCallee = callCom.StaticCallee()
			// *Builtin or any other value indicating a dynamically dispatched function call
			// todo: check some taint flow function in srcpkgs


			//check


			if staticCallee != nil {
				// staticCalle is the targetMethod of the call
				vc = ck.GetValueContext(staticCallee, callCom.Args, c.GetIn(), false)
				log.Debugf("callvalue: %s,callinstr: %s, staticCallee: %s", call.Value().String(),callCom.String(),staticCallee.String())

			}
			//log.Printf("callsite - 3  :%s\n",c.String())

		case *ssa.MakeClosure:
			fn, ok := call.Fn.(*ssa.Function)
			if !ok {
				_ = errors.Errorf("unexpected: call(%s).Fn should be of type *ssa.Function", call)
			}
			vc = ck.GetValueContext(fn, call.Bindings, c.GetIn(), true)
			staticCallee = fn
			paramsCaller = call.Bindings
		}
		// the parameters of the call are added to the lattice -> updating the out lattice too
		// SetOut builds the LUP
		//log.Printf("callsite - 4  :%s\n",c.String())
		c.SetOut(c.GetIn()) // local flow
		//log.Printf("callsite - 5  :%s\n",c.String())

		if vc != nil {
			// TODO rename
			ck.updateNewContext(vc, paramsCaller, c, staticCallee, call)
		}

	}
	//log.Debugf("callsite - 2  :%s\n",c.String())

	return nil
}
