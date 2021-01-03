package checker

import (
	"chaincode-checker/go-taint/context"
	"chaincode-checker/go-taint/lattice"
	"chaincode-checker/go-taint/ssautils"
	"github.com/pkg/errors"
	"golang.org/x/tools/go/ssa"
)

func(ck *Checker) matchParams(pcaller []ssa.Value, lcaller lattice.Lattice, callee *ssa.Function, isClosure bool) lattice.Lattice {


	var pcallee []ssa.Value

	if isClosure{
		fvs := callee.FreeVars
		pcallee = make([]ssa.Value,len(fvs))
		for i,fv := range fvs{
			pcallee[i] = fv
		}
	}else{
		params := callee.Params
		pcallee = make([]ssa.Value,len(params))
		for i,p := range params{
			pcallee[i] = p
		}
	}

	var ret lattice.Lattice

	if ck.checkerCfg.IsPtr{
		ret = lattice.NewLatticePointer(0,ck.ValToPtr)
	}else{
		ret = lattice.NewLattice(0)
	}

	for i,val := range pcaller{
		ret.SetTag(pcallee[i],lcaller.GetTag(val))
	}

	return ret

}

func isEntryNode(n ssa.Instruction) bool {
	parentFunc := n.Parent()

	if parentFunc.Blocks[0].Instrs[0] == n{
		return true
	}
	return false
}

func (ck *Checker)updateEntryContext(n *context.ContextCallSuite) error  {
	isEntry := isEntryNode(n.GetNode())

	if !isEntry{
		var upLattice lattice.Lattice
		if ck.checkerCfg.IsPtr{
			upLatticePtr := lattice.NewLatticePointer(0,ck.ValToPtr)

			//todo can delete?
			upLatticePtr.SetPtrs(ck.ValToPtr)
			upLattice = upLatticePtr
		}else{
			upLattice = lattice.NewLattice(0)
		}

		node := n.GetNode()
		block := node.Block()
		// 1) node is first element in Block (=/= entry node (first block and first element within the first block):
		//    Get last instruction of predecessor (idom)
		// 2) node is withing the Block:
		//    Get the lattice of the instruction before node

		if block.Instrs[0] == node{
			preds := block.Preds
			for i,b := range preds{
				lasti := b.Instrs[len(b.Instrs) - 1]
				LoopCcsPool:
					for _, ccs := range ck.ContextCallSuites{
						if ccs.GetNode() == lasti{
							if ccs.GetValueContext().SameId(n.GetValueContext()){
								if i == 0{
									upLattice = ccs.GetOut()
								}else{
									var err error
									upLattice,err = upLattice.LeastUpperBound(ccs.GetOut())
									if err != nil{
										return errors.Wrap(err, " failed lup of predecessors ")
									}
								}
								continue LoopCcsPool
							}
						}
				}
			}
		}else{
		LoopInstr:
			for i, instr := range block.Instrs{
					if instr == node{
						prevnode := block.Instrs[i - 1]
						LoopCcsPool2:
							for _,ccs := range ck.ContextCallSuites{
								if ccs.GetNode() == prevnode{
									if ccs.GetValueContext().SameId(n.GetValueContext()){
										upLattice = ccs.GetOut()
										break LoopCcsPool2
									}
								}
							}
							break LoopInstr
					}
				}
		}
		n.SetIn(upLattice)

	}else{
		ctx := n.GetValueContext()
		n.SetIn(ctx.GetEntryValue())
	}
	return nil
}


func (ck *Checker) AddSuccessor(n *context.ContextCallSuite ) {
	sucs := getSuccessors(n.GetNode())
	for _, s := range sucs {
		c := getInstrContext(n, s, ck.ContextCallSuites)
		if c == nil {
			c = ck.NewCtxCallSuites(n.GetValueContext(), s)
			c.SetIn(n.GetOut())
		}
		ck.taskList.Add(c)
	}
	// For node send: Add all calls which uses the channel als successor
	send, ok := n.GetNode().(*ssautils.Send)
	if ok {
		for _, s := range send.GetCalls() {
			// should only one context, because every node should exists once within each context.
			c := ck.getChannelContext(n, s)
			if c == nil {
				c = ck.NewCtxCallSuites(n.GetValueContext(), s)
				// Overapproximate and set the out lattice of the sending node
				c.SetIn(n.GetOut())
			} else {
				newValue := n.GetOut().GetTag(send.Send.Chan)
				c.GetIn().SetTag(send.Send.Chan, newValue)
			}
			ck.taskList.Add(c)
		}
	}
}






func(ck *Checker) ctxTransToAnotherX(x *context.ContextCallSuite)[]*context.ContextCallSuite {
	var another []*context.ContextCallSuite

	if x != nil && x.GetValueContext() != nil{
		for _,t := range ck.Transitions{
			//1. targetctx == x.valuectx && start != target
			if t.GetTargetContext().Equal(x.GetValueContext()) && t.GetStartContext() != t.GetTargetContext(){
				for _,ccs := range ck.ContextCallSuites{

					//2.transition流的起点 == ccs的valuectx 并且ccs的指令和transition的指令相同
					if ccs.GetValueContext().Equal(t.GetStartContext()) && ccs.GetNode() == t.GetNode(){
						another = append(another,ccs)
					}
				}
			}
		}
	}
	return another
}

func getSuccessors(i ssa.Instruction) []ssa.Instruction {
	var succs []ssa.Instruction
	b := i.Block()
	if i == b.Instrs[len(b.Instrs)-1] {
		for _, succ := range b.Succs {
			succs = append(succs, succ.Instrs[0])
		}
		/*	dominees := b.Dominees()
			for _, d := range dominees {
				succs = append(succs, d.Instrs[0])
			} */
	} else {
		for j, k := range b.Instrs {
			if k == i {
				succs = append(succs, b.Instrs[j+1])
			}
		}
	}
	return succs
}

func getInstrContext(n *context.ContextCallSuite, s ssa.Instruction, ccss []*context.ContextCallSuite) *context.ContextCallSuite {
	var c *context.ContextCallSuite = nil

	call,isCall := s.(ssa.CallInstruction)
	noUpdate := true

	if s.Parent() == n.GetValueContext().GetMethod(){
		for _,ccs := range ccss	{
			if ccs.GetNode() == s{
				if isCall{
					ins := ccs.GetIn()
					args := call.Common().Args
					for _, in := range args{
						nin := n.GetOut().GetTag(in)
						nccs := ins.GetTag(in)
						eq := nin.Equal(nccs)
						if !eq{
							noUpdate = false
						}
					}
					if noUpdate{
						c = ccs
					}
				}else{
					c = ccs
				}
			}
		}
	}
	return c
}

func (ck *Checker) getChannelContext(n *context.ContextCallSuite, s ssa.Instruction) *context.ContextCallSuite {
	if s.Parent() == n.GetValueContext().GetMethod() {
		for _, ccs := range ck.ContextCallSuites {
			if ccs.GetNode() == s {
				return ccs
			}
		}
	}
	return nil
}

// Match statement tries to match the return values of the calle to the returned values of the caller
func  matchRetStatements(calleeL lattice.Lattice, callerL lattice.Lattice, calleeI *ssa.Function, callerI ssa.Instruction) lattice.Lattice {
	blocks := calleeI.Blocks
	var lupTag []lattice.LatticeTag
	for _, bb := range blocks {
		// only the last element of a basic block can be a return statement
		retVal := bb.Instrs[len(bb.Instrs)-1]
		retValRes, ok := retVal.(*ssa.Return)
		if ok {
			res := retValRes.Results
			for _, r := range res {
				lupTag = append(lupTag, calleeL.GetTag(r))
			}
		}
	}
	// Unprecise: Match lupTag to one value
	lupval := lattice.Uninitialized
	if len(lupTag) > 0 {
		lupval = lupTag[0]
		for _, val := range lupTag[1:] {
			lupval = lupval.LeastUpperBound(val)
		}
	}

	// Unprecise set lupVal to callee node (unprecise because of possible extract)
	var callValue ssa.Value
	switch c := callerI.(type) {
	case *ssa.Call:
		callValue = c
	case *ssa.Defer:
		callValue = c.Common().StaticCallee()
	case *ssa.Go:
		callValue = c.Common().StaticCallee()
	}
	retLat := callerL
	//retLat := callerL.DeepCopy()
	_ = retLat.SetTag(callValue, lupval)
	return retLat
}
