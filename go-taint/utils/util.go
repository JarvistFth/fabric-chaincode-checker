package utils

import (
	"github.com/pkg/errors"
	"go/token"
	"go/types"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
	"strings"
)

func HandleError(err error, msg string) error {
	if err != nil{
		err = errors.Wrap(err,msg)
	}
	return err
}


func IsPointerVal(i ssa.Value) (canPoint bool, val ssa.Value) {
	if call, ok := i.(*ssa.Call); ok {
		val = call.Common().Value
	} else {
		val = i
	}
	return pointer.CanPoint(val.Type()), val
}

// IsIndirectPtr checks whether the value is an indirect pointer value
// In the positive case the function returns the ssa.Value.
func IsIndirectPtr(i ssa.Value) (canPoint bool, val ssa.Value) {
	if call, ok := i.(*ssa.Call); ok {
		val = call.Common().Value
	} else {
		val = i
	}
	// call function like described in the api
	//	fmt.Printf("val: %s | val.Type() %v | val.Type().Underlying() %v\n", val, val.Type(), val.Type().Underlying())
	_, isRange := val.(*ssa.Range)
	if isRange {
		return false, val
	}
	_, isPointer := val.Type().Underlying().(*types.Pointer)
	if !isPointer {
		return false, val
	}

	return pointer.CanPoint(val.Type().Underlying().(*types.Pointer).Elem()), val
}

func ReplaceSend(pkgs []*ssa.Package) {
	chToFuncs := findChannels(pkgs)
	for _, pkg := range pkgs {
		for name, memb := range pkg.Members {
			if memb.Token() == token.FUNC {
				f := pkg.Func(name)
				for _, b := range f.Blocks {
					for n, i := range b.Instrs {
						val, ok := i.(*ssa.Send)
						if ok {
							replace := &Send{&send{val, chToFuncs[val.Chan]}}
							b.Instrs[n] = replace
						}
					}
				}
			}
		}
	}
}

// fincChannels finds for all channels the corresponding call instructions
func findChannels(mains []*ssa.Package) map[ssa.Value][]ssa.CallInstruction {
	var callCom *ssa.CallCommon
	chfuncs := make(map[ssa.Value][]ssa.CallInstruction, 0)
	for _, pkg := range mains {
		for name, memb := range pkg.Members {
			if memb.Token() == token.FUNC {
				f := pkg.Func(name)
				for _, b := range f.Blocks {
					for _, i := range b.Instrs {
						callCom = nil
						switch it := i.(type) {
						case *ssa.Go:
							callCom = it.Common()
						case *ssa.Defer:
							callCom = it.Common()
						case *ssa.Call:
							callCom = it.Common()
						}
						if callCom != nil {
						args:
							for _, v := range callCom.Args {
								mc, ok := v.(*ssa.MakeChan)
								i, _ := i.(ssa.CallInstruction)
								if ok {
									calls := chfuncs[mc]
									if calls == nil {
										calls = make([]ssa.CallInstruction, 0)
									}
									chfuncs[mc] = append(calls, i)
									continue args
								}
								// TODO: find better solution
								underly := v.Type().Underlying()
								isChan := strings.Contains(underly.String(), "chan")
								if isChan {
									calls := chfuncs[v]
									if calls == nil {
										calls = make([]ssa.CallInstruction, 0)
									}
									chfuncs[v] = append(calls, i)
								}
							}
						}
					}
				}
			}
		}
	}
	return chfuncs
}

