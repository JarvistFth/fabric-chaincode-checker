package context

import (
	"chaincode-checker/taint_analysis/Errors"
	"chaincode-checker/taint_analysis/config"
	"chaincode-checker/taint_analysis/latticer"
	"chaincode-checker/taint_analysis/logger"
	"chaincode-checker/taint_analysis/utils"
	"go/token"
	"golang.org/x/tools/go/ssa"
)

func (c *CallGraph) LoopInstr() {
	for !c.instrs.Empty(){
		instrCtx := c.instrs.RemoveFront()
		instruction := instrCtx.GetInstr()
		log.Debug(instruction.String())
		switch instr := instruction.(type) {
		case ssa.Value:
			//flow
			latout := LatticeTable.GetLattice(instr)
			instrCtx.SetLatticeOut(latout)
			switch instrWithVal := instr.(type) {
			case *ssa.Alloc, *ssa.MakeChan, *ssa.MakeMap, *ssa.MakeSlice:
				//untainted
				latout.Untaint()
				log.Debug(latout.String())
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
				latout.LeastUpperBound(latin)
				log.Debug(latout.String())

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
				lat1.LeastUpperBound(lat2)
				latout.LeastUpperBound(lat1)


			case *ssa.Phi:
				edges := instrWithVal.Edges
				for _, edge := range edges {
					lat := LatticeTable.GetLattice(edge)
					latout.LeastUpperBound(lat)
				}



			case *ssa.Call:
				//call function
				callcom := instrWithVal.Call
				//ret := instrWithVal.Call.Value
				args := instrWithVal.Call.Args
				//log.Debug("callcom:",callcom.String())
				//log.Debugf("instrWithVal - val:%s, parent:%s, name:%s, string:%s",instrWithVal.Value(),instrWithVal.Parent(),instrWithVal.Name(),instrWithVal.String())
				//log.Debugf("ret val:%s",instrWithVal.Parent())
				//check source and sink
				issource,types := CheckSource(instrCtx)
				if issource {
					latout.SetTag(latticer.Tainted)
					latout.SetMsg(types)
					Errors.NewErrMessage(instrWithVal, callcom,latout.GetMsg())
					log.Debug(latout.String())
					continue
				}

				issink := CheckSink(instrCtx)
				if issink {
					//sink throw error
					handleSinkDetection(instrWithVal,callcom)
					continue
				}

				if issink || issource {
					continue
				}


				issdkfunc := CheckSDK(instrCtx)

				if issdkfunc{
					log.Debug("sdk function")
					for _,arg := range args{
						arglat := LatticeTable.GetLattice(arg)
						latout.LeastUpperBound(arglat)
					}
					log.Debug(latout.String())
					continue
				}

				if callcom.IsInvoke() {
					//todo invoke mode call
				} else {
					staiccallee := instrWithVal.Common().StaticCallee()

					fc,_ := GetFunctionContext(staiccallee, false, true)
					fc.LoopInstr()
					retlattice := fc.GetReturnLattice()
					for _,rets := range retlattice {
						latout.LeastUpperBound(rets)
					}
					log.Debug(latout.String())
				}
				break

			case *ssa.Select:
				//select func
				break

			case *ssa.UnOp:
				//
				log.Warningf("unop ctx:%s", instrWithVal.String())
				if instrWithVal.Op != token.ARROW && instrWithVal.Op != token.MUL {
					log.Warning("un op but not pointer")
					//valx := instrWithVal.X
					//latx := LatticeTable.GetLattice(valx)

				} else {
					UnOpPtr(latout, instrWithVal,config.WorkingProject.PtrResult)
					log.Debug("un op with pointer:",latout.String())
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

		case *ssa.Go, *ssa.Defer:
			switch valtype := instr.(type) {
			case *ssa.Go:
				msg := Errors.NewErrMessage(valtype,valtype.Call,Errors.USE_GOROUTINE)
				log.Warningf("%s",msg)
			}


		case *ssa.DebugRef, *ssa.RunDefers:

		case *ssa.Jump:
			//jump

		case *ssa.Return:
			//return
			rets := instr.Results
			for _,ret := range rets{
				c.retLattice = append(c.retLattice,LatticeTable.GetLattice(ret))
			}
		case *ssa.Panic:
			break

		case *ssa.Store:
			//*x = y
			addr := instr.Addr
			val := instr.Val

			latval := LatticeTable.GetLattice(val)
			lataddr := LatticeTable.GetLattice(addr)
			valtag := latval.GetTag()
			valmsg := latval.GetMsg()
			lataddr.SetTag(valtag)
			lataddr.SetMsg(valmsg)
			if ok, addrp := utils.IsPointerVal(addr); ok {
				var lataddr = lataddr.(*latticer.LatticePointer)
				q := config.WorkingProject.PtrResult.Queries[addrp]
				qset := q.PointsTo()
				labels := qset.Labels()
				//指针指向的value的tag要改
				for _, l := range labels {
					labelvalue := l.Value()
					log.Debugf("labelvalue:%s",labelvalue.Name())
					LatticeTable.GetLattice(labelvalue).SetTag(valtag)
					LatticeTable.GetLattice(labelvalue).SetMsg(valmsg)
				}
				//是别名的指针，它对应的value的tag也要改
				for ssav, p := range config.WorkingProject.ValToPtrs {
					if p.MayAlias(*lataddr.GetPtr()) {
						log.Debugf("aliasvalue:%s",ssav.Name())
						LatticeTable.GetLattice(ssav).SetTag(valtag)
						LatticeTable.GetLattice(ssav).SetMsg(valmsg)
					}
				}
			}
			log.Debug("after store ptr ",LatticeTable.String())

		case *ssa.MapUpdate:
			valmap := instr.Map
			valkey := instr.Key
			val := instr.Value
			maplat := LatticeTable.GetLattice(valmap)
			keylat := LatticeTable.GetLattice(valkey)
			vallat := LatticeTable.GetLattice(val)
			keylat.LeastUpperBound(vallat)
			maplat.LeastUpperBound(keylat)

		default:
			if instrCtx.GetLatticeOut() != nil{
				log.Debug(instrCtx.GetLatticeOut().String())
			}
		}
	}
	//log.Debug(c.String())
	//log.Debug(LatticeTable.String())
}

func(c *CallGraph) analyzeInstructions(ssaFun *ssa.Function, isPtr bool)  {
	pkg := ssaFun.Package()
	analyze := false
	// check whether the pkg is defined within the packages which should analyzed
ctxtfor:
	for _, p := range config.WorkingProject.Packages {
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
