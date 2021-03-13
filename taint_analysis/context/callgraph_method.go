package context

import (
	"chaincode-checker/taint_analysis/latticer"
	"chaincode-checker/taint_analysis/logger"
	"chaincode-checker/taint_analysis/project_config"
	"chaincode-checker/taint_analysis/utils"
	"go/token"
	"golang.org/x/tools/go/ssa"
)

func (c *CallGraph) LoopInstr() {
	for !c.instrs.Empty(){
		instrCtx := c.instrs.RemoveFront()
		switch instr := instrCtx.GetInstr().(type) {
		case ssa.Value:
			//flow

			switch valtype := instr.(type) {
			case *ssa.Alloc, *ssa.MakeChan, *ssa.MakeMap, *ssa.MakeSlice:
				//untainted
				instrCtx.GetLatticeOut().Untaint()
				break
			case *ssa.ChangeInterface, *ssa.ChangeType, *ssa.Convert, *ssa.Extract, *ssa.Field, *ssa.FieldAddr, *ssa.Index, *ssa.MakeInterface, *ssa.Next, *ssa.Range, *ssa.Slice, *ssa.TypeAssert:

				var op ssa.Value
				switch valtype := instr.(type) {
				case *ssa.ChangeInterface:
					op = valtype.X
				case *ssa.ChangeType:
					op = valtype.X
				case *ssa.Convert:
					op = valtype.X
					log.Debugf("convert: %s",op.String())
				case *ssa.Extract:
					op = valtype.Tuple
				case *ssa.Field:
					op = valtype.X
				case *ssa.FieldAddr:
					op = valtype.X
				case *ssa.Index:
					op = valtype.X
					//todo may check array index?
				case *ssa.MakeInterface:
					op = valtype.X
				case *ssa.Next:
					op = valtype.Iter
				case *ssa.Range:
					op = valtype.X
				case *ssa.Slice:
					op = valtype.X
				case *ssa.TypeAssert:
					op = valtype.X
				}
				//new lattice in
				latin := LatticeTable.GetLattice(op)
				latout := LatticeTable.GetLattice(valtype)
				//c.AppendLatticeIn(latin)

				//look for op tag
				//SetLatticeInAndOutTag(c)
				latout.LeastUpperBound(latin)
				break

			case *ssa.BinOp, *ssa.IndexAddr, *ssa.Lookup:
				var op1, op2 ssa.Value
				switch valtype := instr.(type) {
				case *ssa.BinOp:
					op1 = valtype.X
					op2 = valtype.Y
				case *ssa.IndexAddr:
					op1 = valtype.X
					op2 = valtype.Index
				case *ssa.Lookup:
					op1 = valtype.X
					op2 = valtype.Index
				}
				lat1 := LatticeTable.GetLattice(op1)
				lat2 := LatticeTable.GetLattice(op2)
				latout := LatticeTable.GetLattice(valtype)
				lat1.LeastUpperBound(lat2)
				latout.LeastUpperBound(lat1)
				//c.AppendLatticeIn(lat1, lat2)

				//look for op tag
				//SetLatticeInAndOutTag(c)
				//double op
				break

			case *ssa.Phi:
				edges := valtype.Edges
				latout := LatticeTable.GetLattice(valtype)
				for _, edge := range edges {
					lat := LatticeTable.GetLattice(edge)
					latout.LeastUpperBound(lat)
				}

				//SetLatticeInAndOutTag(c)
				//cfg phi
				break

			case *ssa.Call:
				//call function
				//valtype.Common().
				//args := valtype.Call.Args
				//method := valtype.Call.Method
				//value := valtype.Call.Value
				callcom := valtype.Common()
				//check source and sink
				issource := CheckSource(c)
				if issource {
					lat := LatticeTable.GetLattice(instr)
					lat.SetTag(latticer.Tainted)
				}

				issink := CheckSink(c)
				if issink {
					//sink throw error
					handleSinkDetection(callcom)
					break
				}

				if issink || issource {
					break
				}

				if callcom.IsInvoke() {
					//todo invoke mode call
				} else {
					staiccallee := valtype.Common().StaticCallee()

					fc,_ := GetFunctionContext(staiccallee, false, IsPtr)
					fc.LoopInstr()
					retlattice := fc.GetReturnLattice()
					ret := valtype.Call.Value
					retlat := LatticeTable.GetLattice(utils.GenKeyFromSSAValue(ret),ret)

				}

				break

			case *ssa.Select:
				//select func
				break

			case *ssa.UnOp:
				//
				valtype.
				log.Warningf("unop ctx:%s",valtype.String())
				if valtype.Op != token.ARROW && valtype.Op != token.MUL {
					log.Warning("un op but not pointer")
					valx := valtype.X
					latx := LatticeTable.GetLattice(valx)

					c.AppendLatticeIn(latx)
					SetLatticeInAndOutTag(c)
				} else {
					log.Warning("un op with pointer")
					LatticeTable.GetLattice(valtype)
					UnOpPtr(valtype,project_config.WorkingProject.PtrResult)
				}
			}

		case *ssa.Send:
			// val1 <- val2
			val1 := instr.Chan
			val2 := instr.X
			latin := LatticeTable.GetLattice(val2)
			latout := LatticeTable.GetLattice(val1)
			instrCtx.SetLatticeIn(latin)
			latout.LeastUpperBound(latin)
			break

		case *ssa.Go, *ssa.Defer:
			switch valtype := instr.(type) {
			case *ssa.Go:
				issink := CheckSink(c)
				if issink {
					//sink throw error
					break
				}

				callcom := valtype.Common()
				if callcom.IsInvoke() {
					//todo invoke mode call
				} else {
					staiccallee := valtype.Common().StaticCallee()

					GetFunctionContext(staiccallee, false, Config.IsPtr)

				}

			}

			break

		case *ssa.DebugRef, *ssa.RunDefers:
			break

		case *ssa.Jump:
			//jump
			break
		case *ssa.Return:
			//return
			rets := instr.Results
			for _,ret := range rets{
				c.retLattice = append(c.retLattice,LatticeTable.GetLattice(ret))
			}
			break
		case *ssa.Panic:
			break

		case *ssa.Store:
			addr := instr.Addr
			val := instr.Val

			latval := LatticeTable.GetLattice(val)
			lataddr := LatticeTable.GetLattice(val)
			valtag := latval.GetTag()
			lataddr.SetTag(valtag)
			if ok, addrp := utils.IsPointerVal(addr); ok {
				var lataddr = lataddr.(*latticer.LatticePointer)
				q := project_config.WorkingProject.PtrResult.Queries[addrp]
				qset := q.PointsTo()
				labels := qset.Labels()
				//指针指向的value的tag要改
				for _, l := range labels {
					labelvalue := l.Value()
					LatticeTable.GetLattice(labelvalue).SetTag(valtag)
				}
				//是别名的指针，它对应的value的tag也要改
				for ssav, p := range project_config.WorkingProject.ValToPtrs {
					if p.MayAlias(*lataddr.GetPtr()) {
						LatticeTable.GetLattice(ssav).SetTag(valtag)
					}
				}
			}

			break

		case *ssa.MapUpdate:
			valmap := instr.Map
			valkey := instr.Key
			val := instr.Value
			maplat := LatticeTable.GetLattice(valmap)
			keylat := LatticeTable.GetLattice(valkey)
			vallat := LatticeTable.GetLattice(val)
			keylat.LeastUpperBound(vallat)
			maplat.LeastUpperBound(keylat)
			break

		}
	}
}

func(c *CallGraph) analyzeInstructions(ssaFun *ssa.Function, isPtr bool)  {
	pkg := ssaFun.Package()
	analyze := false
	// check whether the pkg is defined within the packages which should analyzed
ctxtfor:
	for _, p := range project_config.WorkingProject.Packages {
		if p == pkg {
			analyze = true
			break ctxtfor
		}
	}
	// only add the blocks and instructions if the package should be analyzed.
	if analyze {
		ssaFun.WriteTo(logger.LogFile)
		for _, block := range ssaFun.Blocks {
			block.Dominees()
			for _, instr := range block.Instrs {
				// build a new context call site for every instruction within the main value context
				ic := NewInstructionContext(c, instr,isPtr)
				//log.Debug(c.String())
				c.instrs.PushBack(ic)
			}
		}
	}
}



