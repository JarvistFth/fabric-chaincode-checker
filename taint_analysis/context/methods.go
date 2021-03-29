package context

import (
	"chaincode-checker/taint_analysis/Errors"
	"chaincode-checker/taint_analysis/latticer"
	"chaincode-checker/taint_analysis/config"
	"chaincode-checker/taint_analysis/taint_config"
	"chaincode-checker/taint_analysis/utils"
	"fmt"
	"github.com/emirpasic/gods/sets/hashset"
	"go/types"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
	"strings"
	"unicode"
	"unicode/utf8"
)

const(
	TAINT_RANDOM = "RANDOM_FUNCTION"
	TAINT_TIME = "TIME_FUNCTION"
	TAINT_GLOBAL = "GLOBAL"
	TAINT_FILE = "OUTSIDE_FILE_OPEN"
	TIANT_CMD = "OUTSIDE_COMMAND_EXEC"

)

func CheckSource(c *InstructionContext) (bool,string) {
	if c.IsCall(){
		call := c.GetInstr().(ssa.CallInstruction)
		callcom := call.Common()
		sig,callee,isig := getSignature(callcom)
		for _, source := range taint_config.SSConfig.Sources{
			//log.Debugf("getSig: %s, call:%s, source.Sig:%s, source.callee:%s",sig,call,source.GetSignature(),source.GetCallee())
			if source.IsInterface {
				//log.Debugf("source interface source, getSig: %s, source.Sig: %s",iSig,source.GetSignature())
				if isig == source.Signature {
					return true,source.Type
				}
			}
			if sig == source.Signature {
				if callee == source.Callee {
					return true,source.Type
				}
			}
		}
		return false,""
	}else{
		log.Panicf("error!! instr:%s is not call instr",c.GetInstr().String())
		return false,""
	}
}

func CheckSink(c *InstructionContext) bool {
	if c.IsCall(){
		call := c.GetInstr().(ssa.CallInstruction)
		callcom := call.Common()
		sig,callee,isig := getSignature(callcom)
		for _, source := range taint_config.SSConfig.Sinks{
			//log.Debugf("getSig: %s, call:%s, source.Sig:%s, source.callee:%s",sig,call,source.GetSignature(),source.GetCallee())
			if source.IsInterface {
				//log.Debugf("source interface source, getSig: %s, source.Sig: %s",iSig,source.GetSignature())
				if isig == source.Signature {
					return true
				}
			}
			if sig == source.Signature {
				if callee == source.Callee {
					return true
				}
			}
		}
		return false
	}else{
		log.Panicf("error!! instr:%s is not call instr",c.GetInstr().String())
		return false
	}
}

func CheckSDK(c *InstructionContext) bool {
	if c.IsCall(){
		call := c.GetInstr().(ssa.CallInstruction)
		callcom := call.Common()
		sig,callee,isig := getSignature(callcom)
		for _, source := range taint_config.SSConfig.SDKFunctions{
			//log.Debugf("getSig: %s, call:%s, source.Sig:%s, source.callee:%s",sig,call,source.Signature,source.Callee)
			if source.IsInterface {
				//log.Debugf("source interface source, getSig: %s, source.Sig: %s",iSig,source.GetSignature())
				if isig == source.Signature {
					return true
				}
			}
			if sig == source.Signature {
				if callee == source.Callee {
					return true
				}
			}
		}
		return false
	}else{
		log.Panicf("error!! instr:%s is not call instr",c.GetInstr().String())
		return false
	}
}

func handleSinkDetection(table LatticeMap, i ssa.Instruction,c ssa.CallCommon)  {
	val := c.Value
	var taintArgs []ssa.Value
	lat := table.GetLattice(val)

	if lat.GetTag() == latticer.Tainted || lat.GetTag() == latticer.Both{
		taintArgs = append(taintArgs,val)
	}

	args := c.Args
	var msg string
	set := hashset.New()

	for _,arg := range args{
		lat := table.GetLattice(arg)
		if lat.GetTag() == latticer.Tainted || lat.GetTag() == latticer.Both{
			taintArgs = append(taintArgs,arg)
			argLatMsg := lat.GetMsg()
			if set.Contains(argLatMsg) {
				continue
			}
			set.Add(argLatMsg)
			msg += fmt.Sprintf("arg:%s with: %s\n",arg.Name(),argLatMsg)
		}
		if config.Config.WithPtr{
			if latptr,ok := lat.(*latticer.LatticePointer);ok{
				ptr := latptr.GetPtr()
				if ptr != nil{
					for ssav,p := range config.WorkingProject.ValToPtrs{
						if p.MayAlias(*ptr){
							tag,_ := table.GetTag(utils.GenKeyFromSSAValue(ssav))
							if tag == latticer.Tainted || tag == latticer.Both{
								taintArgs = append(taintArgs,arg)
								argLatMsg := lat.GetMsg()
								if set.Contains(argLatMsg) {
									continue
								}
								set.Add(argLatMsg)
								msg += fmt.Sprintf("arg:%s with: %s\n",arg.Name(),argLatMsg)
							}
						}
					}
				}

			}
		}
	}

	if len(taintArgs) > 0{
		log.Errorf("sink function with tainted flag!!")
		Errors.NewErrMessage(i,c,msg)
	}

}


func getSignature(c *ssa.CallCommon) (signature, callee, iSignature string) {
	// [vs: can this signature be an interface here? If yes, do we miss "up-casted" sources?]
	// Get the signatuer and iterate through the sources

	//log.Infof("c get sig: %s",c.String())

	if c.IsInvoke(){
		typename := c.Value.Type().String()
		relativepkgs := strings.Split(typename,"/")
		objname := relativepkgs[len(relativepkgs) - 1]
		callee = objname + "." + c.Method.Name()
		signature = c.Signature().String()
		log.Debugf("invoke call comm : callee: %s signature: %s",callee,signature)
		return
	}

	signature = c.Signature().String()
	if c.StaticCallee() != nil {
		callee = c.StaticCallee().String()
	}

	var sigSlice []string



	if types.IsInterface(c.Signature().Underlying()) {
		// Signature for an interface does not contain names for the parameters
		sigI := c.Signature().String()
		//log.Debugf("sigI: %s",c.Signature().String())
		// splits a string into a string slice.
		// Each element in the slice consists only of an letter, a number, [, ], (,) or a *
		f := func(c rune) bool {
			r1, _ := utf8.DecodeRuneInString("[")
			r2, _ := utf8.DecodeRuneInString("]")
			r3, _ := utf8.DecodeRuneInString("*")
			r4, _ := utf8.DecodeRuneInString("(")
			r5, _ := utf8.DecodeRuneInString(")")
			return !unicode.IsLetter(c) && !unicode.IsNumber(c) && c != r1 && c != r2 && c != r3 && c != r4 && c != r5
		}
		sigSlice = strings.FieldsFunc(sigI, f)
		for i, s := range sigSlice {
			paramsReady := false
			retReady := true
			retStart := 1
			if i == 0 {
				if !strings.Contains(s, "func()") {
					// func(name -> func(
					withoutName := strings.SplitAfter(s, "(")
					sigSlice[i] = withoutName[0]
					paramsReady = true
				}
			}

			if !paramsReady {
				if i%2 != 0 {
					paramsReady = strings.Contains(s, ")")
					if paramsReady {
						retReady = false
						retStart = i + 1
					}
				} else {
					sigSlice[i] = ""
				}
			}

			if !retReady {
				if !strings.Contains(s, ")") {
					if (i-retStart)%2 != 0 {
						sigSlice[i] = ""
					}
				}
			}
		}
	}
	for _, s := range sigSlice {
		iSignature += s
	}
	return
}


func UnOpPtr(table LatticeMap,latout latticer.Lattice, e *ssa.UnOp, ptrResult *pointer.Result) {
	addr := e.X
	if _,ok:=addr.(*ssa.Global);ok{
		latout.SetTag(latticer.Tainted)
		latout.SetMsg(TAINT_GLOBAL)
		return
	}
	latticeVal := table.GetLattice(addr)
	valtag := latticeVal.GetTag()



	//qset := q.PointsTo()
	//				labels := qset.Labels()
	//				//指针指向的value的tag要改
	//				for _, l := range labels {
	//					labelvalue := l.Value()
	//					LatticeTable.GetLattice(labelvalue).SetTag(valtag)
	//				}
	//				//是别名的指针，它对应的value的tag也要改
	//				for ssav, p := range config.WorkingProject.ValToPtrs {
	//					if p.MayAlias(*lataddr.GetPtr()) {
	//						LatticeTable.GetLattice(ssav).SetTag(valtag)
	//					}
	//				}

	if ptrResult != nil{
		if ok, valr := utils.IsPointerVal(addr); ok {
			q := ptrResult.Queries[valr]
			labels := q.PointsTo().Labels()
			for _, label := range labels {
				labelval := label.Value()
				table.GetLattice(labelval).SetTag(valtag)
			}
			//for ssav, p := range config.WorkingProject.ValToPtrs {
			//	if p.MayAlias(*lataddr.GetPtr()) {
			//		LatticeTable.GetLattice(ssav).SetTag(valtag)
			//	}
			//}
		}

		if ok, valr := utils.IsIndirectPtr(addr); ok {
			q := ptrResult.Queries[valr]
			labels := q.PointsTo().Labels()
			for _, label := range labels {
				labelval := label.Value()
				table.GetLattice(labelval).SetTag(valtag)
			}
			//for ssav, p := range config.WorkingProject.ValToPtrs {
			//	if p.MayAlias(*lataddr.GetPtr()) {
			//		LatticeTable.GetLattice(ssav).SetTag(valtag)
			//	}
			//}
		}
	}
}



