package checker

import (
	"chaincode-checker/taint_analysis/context"
	"chaincode-checker/taint_analysis/latticer"
	"chaincode-checker/taint_analysis/logger"
	"chaincode-checker/taint_analysis/project_config"
	"chaincode-checker/taint_analysis/utils"
	"go/token"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
)

func InitFunctionContext(ssaFunc *ssa.Function) {
	f,_ := context.GetFunctionContext(ssaFunc,false,Config.IsPtr)
	log.Debugf("init function: %s",f.GetName())

	analyzeFuntionCtx(ssaFunc,f)
}


func analyzeFuntionCtx(ssaFun *ssa.Function, vc *context.FunctionContext) {
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
			for _, instr := range block.Instrs {
				// build a new context call site for every instruction within the main value context
				c := context.NewInstructionContext(vc, instr,Config.IsPtr)
				//log.Debug(c.String())
				TasksList.PushBack(c)
			}
		}
	}
}

func HandleInstr(c *context.InstructionContext) {
	switch instr := c.GetInstr().(type) {
	case ssa.Value:
		//flow

		switch valtype := instr.(type) {
		case *ssa.Alloc, *ssa.MakeChan, *ssa.MakeMap, *ssa.MakeSlice:
			//untainted
			c.GetLatticeOut().Untaint()
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
				log.Debugf("convert: %s",valtype.String())
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
			latout := LatticeTable.GetLattice(utils.GenKeyFromSSAValue(valtype), valtype)
			latin := LatticeTable.GetLattice(utils.GenKeyFromSSAValue(op),op)
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
			lat1 := LatticeTable.GetLattice(utils.GenKeyFromSSAValue(op1), op1)
			lat2 := LatticeTable.GetLattice(utils.GenKeyFromSSAValue(op2), op2)
			latout := LatticeTable.GetLattice(utils.GenKeyFromSSAValue(valtype),valtype)
			lat1.LeastUpperBound(lat2)
			latout.LeastUpperBound(lat1)
			//c.AppendLatticeIn(lat1, lat2)

			//look for op tag
			//SetLatticeInAndOutTag(c)
			//double op
			break

		case *ssa.Phi:
			edges := valtype.Edges
			latout := LatticeTable.GetLattice(utils.GenKeyFromSSAValue(valtype),valtype)
			for _, edge := range edges {
				lat := LatticeTable.GetLattice(utils.GenKeyFromSSAValue(edge), edge)
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
				lat := LatticeTable.GetLattice(utils.GenKeyFromSSAValue(instr), instr)
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

				context.GetFunctionContext(staiccallee, false, Config.IsPtr)

			}

			break

		case *ssa.Select:
			//select func
			break

		case *ssa.UnOp:
			//
			log.Warningf("unop ctx:%s",valtype.String())
			if valtype.Op != token.ARROW && valtype.Op != token.MUL {
				log.Warning("un op but not pointer")
				valx := valtype.X
				latx := LatticeTable.GetLattice(utils.GenKeyFromSSAValue(valx), valx)
				c.AppendLatticeIn(latx)
				SetLatticeInAndOutTag(c)
			} else {
				log.Warning("un op with pointer")
				LatticeTable.GetLattice(utils.GenKeyFromSSAValue(valtype),valtype)
				UnOpPtr(valtype,project_config.WorkingProject.PtrResult)
			}
		}

	case *ssa.Send:
		// val1 <- val2
		val1 := instr.Chan
		val2 := instr.X
		latin := LatticeTable.GetLattice(utils.GenKeyFromSSAValue(val2), val2)
		c.AppendLatticeIn(latin)
		SetLatticeInTag(c)
		latout := LatticeTable.GetLattice(utils.GenKeyFromSSAValue(val1), val1)
		latout.LeastUpperBound(latin)
		c.SetLatticeOut(latout)
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

				context.GetFunctionContext(staiccallee, false, Config.IsPtr)

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
		break
	case *ssa.Panic:
		break

	case *ssa.Store:
		addr := instr.Addr
		val := instr.Val

		latval := LatticeTable.GetLattice(utils.GenKeyFromSSAValue(val), val)
		lataddr := LatticeTable.GetLattice(utils.GenKeyFromSSAValue(addr), addr)
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
				key := utils.GenKeyFromSSAValue(labelvalue)
				LatticeTable.GetLattice(key, labelvalue).SetTag(valtag)
			}
			//是别名的指针，它对应的value的tag也要改
			for ssav, p := range project_config.WorkingProject.ValToPtrs {
				if p.MayAlias(*lataddr.GetPtr()) {
					LatticeTable.GetLattice(utils.GenKeyFromSSAValue(ssav), ssav).SetTag(valtag)
				}
			}
		}

		break

	case *ssa.MapUpdate:
		valmap := instr.Map
		valkey := instr.Key
		val := instr.Value

		maplat := LatticeTable.GetLattice(utils.GenKeyFromSSAValue(valmap), valmap)
		keylat := LatticeTable.GetLattice(utils.GenKeyFromSSAValue(valkey), valkey)
		vallat := LatticeTable.GetLattice(utils.GenKeyFromSSAValue(val), val)

		keylat.LeastUpperBound(vallat)
		maplat.LeastUpperBound(keylat)
		break

	}
}


func UnOpPtr(e *ssa.UnOp, ptr *pointer.Result){
	value := e.X

	latx := LatticeTable.GetLattice(utils.GenKeyFromSSAValue(value),value)

	log.Warningf("latx:%s",latx.String())

	if ok,valr := utils.IsPointerVal(value);ok{
		log.Warningf("pointerval:%s",valr.String())
		var latp = latx.(*latticer.LatticePointer)
		q := ptr.Queries[valr]
		labels := q.PointsTo().Labels()
		for _,label := range labels{
			log.Debugf("label:%s",label.Value().String())
			LatticeTable.GetLattice(utils.GenKeyFromSSAValue(label.Value()),label.Value()).SetTag(latx.GetTag())
		}

		for ssav, p := range project_config.WorkingProject.ValToPtrs{
			if p.MayAlias(*latp.GetPtr()){
				LatticeTable.GetLattice(utils.GenKeyFromSSAValue(ssav),ssav).SetTag(latx.GetTag())
			}
		}
	}


	if ok,valr := utils.IsIndirectPtr(value);ok{
		log.Warningf("indirect ptr:%s",valr.String())
		var latp = latx.(*latticer.LatticePointer)
		q := ptr.IndirectQueries[valr]
		labels := q.PointsTo().Labels()
		for _,label := range labels{
			LatticeTable.GetLattice(utils.GenKeyFromSSAValue(label.Value()),label.Value()).SetTag(latx.GetTag())
		}

		for ssav, p := range project_config.WorkingProject.ValToPtrs{
			if p.MayAlias(*latp.GetPtr()){
				LatticeTable.GetLattice(utils.GenKeyFromSSAValue(ssav),ssav).SetTag(latx.GetTag())
			}
		}
	}
}
