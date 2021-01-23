package lattice

import (
	"chaincode-checker/go-taint/utils"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
)

type LatticeValueTable map[string]*LatticeValue

func (v LatticeValueTable) GetValue(key string) *LatticeValue  {
	return v[key]
}

func (v LatticeValueTable) Len() int {
	return len(v)
}

func (v LatticeValueTable) GetTag(key string) LatticeTag{
	return v[key].tag
}


func (v *LatticeValueTable) TransferFunction(node ssa.Instruction, ptr *pointer.Result) PlainFF {
	log.Debugf("node: %s\n",node.String())
	switch nType := node.(type) {
	// Handle all cases which returns only the id
	// *ssa.MakeClosure returns only the id, becuase it's a ~function~ call which creates a new context
	case *ssa.DebugRef, *ssa.Jump, *ssa.MakeClosure, *ssa.Panic, *ssa.Return:
		return returnID
		// Handle the cases which operates on one ssa.Value e.g. Type.X and requires a LUP
		// A allocation should set a value to untainted
		// *ssa.MakeInterface is not listed because there construct a new type based upon another type
	case *ssa.Alloc, *ssa.MakeChan, *ssa.MakeMap, *ssa.MakeSlice:
		return returnUntainted
	case *ssa.ChangeInterface, *ssa.ChangeType, *ssa.Convert, *ssa.Extract, *ssa.Field, *ssa.FieldAddr, *ssa.Index, *ssa.MakeInterface, *ssa.Next, *ssa.Range, *ssa.Send, *ssa.Slice, *ssa.TypeAssert, *ssa.UnOp:
		var valX ssa.Value
		switch xType := node.(type) {
		case *ssa.ChangeInterface:
			valX = xType.X
		case *ssa.ChangeType:
			valX = xType.X
		case *ssa.Convert:
			valX = xType.X
		case *ssa.Extract:
			valX = xType.Tuple
		case *ssa.Field:
			valX = xType.X
		case *ssa.FieldAddr:
			valX = xType.X
		case *ssa.Index:
			valX = xType.X
		case *ssa.MakeInterface:
			valX = xType.X
		case *ssa.MakeMap:
			valX = xType.Reserve
		case *ssa.Next:
			valX = xType.Iter
		case *ssa.Range:
			valX = xType.X
		case *ssa.Send:
			valX = xType.X
		case *ssa.Slice:
			valX = xType.X
		case *ssa.TypeAssert:
			valX = xType.X
		case *ssa.UnOp:
			valX = xType.X


			//TODO

			/*	if xType.Op != token.MUL {
					valX = xType.X
				} else {
					return ptrUnOp(xType, lv, ptr)
				} */
		}

		//TODO check global source?
		ff := checkAndHandleGlobalSource(valX)
		if ff == nil{
			return returnLUP(v.GetTag(utils.GenKeyFromSSAValue(valX)))
		}else{
			return ff
		}

		// Handle the cases which operates on two ssa.Values
	case *ssa.BinOp, *ssa.IndexAddr, *ssa.Lookup:
		var val1, val2 ssa.Value
		switch xType := node.(type) {
		case *ssa.BinOp:
			val1 = xType.X
			val2 = xType.Y
		case *ssa.IndexAddr:
			val1 = xType.X
			val2 = xType.Index
		case *ssa.Lookup:
			val1 = xType.X
			val2 = xType.Index
		}
		lVal1 := v.GetTag(utils.GenKeyFromSSAValue(val1))
		lVal2 := v.GetTag(utils.GenKeyFromSSAValue(val2))
		var retLatValuer LatticeTag
		retLatValuer = lVal1.LeastUpperBound(lVal2)
		return returnLUP(retLatValuer)
		// Handle the cases which operates upon an slice
	case *ssa.Phi:
		valArr := nType.Edges
		var tag LatticeTag
		tag = Uninitialized
		for _, ssaVal := range valArr {
			val := v.GetTag(utils.GenKeyFromSSAValue(ssaVal))
			tag = tag.LeastUpperBound(val)
		}
		return returnLUP(tag)
		// Hande the case with three ssa.Values
	case *ssa.MapUpdate:
		// updates a values in Map[Key] to value
		valMap := nType.Map
		valKey := nType.Key
		valValue := nType.Value
		lValMap := v.GetTag(utils.GenKeyFromSSAValue(valMap))
		lValKey := v.GetTag(utils.GenKeyFromSSAValue(valKey))
		var lupMapKey LatticeTag
		lupMapKey = lValMap.LeastUpperBound(lValKey)
		lValValue := v.GetTag(utils.GenKeyFromSSAValue(valValue))
		var lup3Val LatticeTag
		lup3Val = lValValue.LeastUpperBound(lupMapKey)
		return returnLUP(lup3Val)
		// Handle calls
	case *ssa.Call, *ssa.Defer, *ssa.Go:
		//TODO some function need return taint or untainted here
		ff := checkAndHandleSourcesAndsinks(node, v, false)
		if ff == nil {
			return returnID
		} else {
			return ff
		}
	case *ssa.If:
		// handling the ssa representation for an if statement
		return returnID
	case *ssa.RunDefers:
		// pops and invokes the defered calls
	case *ssa.Select:
		// testing whether one of the specified sent or received states is entered
		// TODO describe behaivour for concurrency
	case *ssa.Store:
		// *t1 = t0
		// Addr is of type FieldAddr
		//log.Printf("ssa.Store \n")
		//log.Printf("  Addr: %s | Value: %s\n", nType.Addr, nType.Val)
		value := nType.Val
		return returnLUP(v.GetTag(utils.GenKeyFromSSAValue(value)))

	default:
		return returnID
	}
	return returnID
}


