package lattice

import (
	"chaincode-checker/go-taint/utils"
	"fmt"
	"go/types"
	"golang.org/x/tools/go/ssa"
	"log"
	"strings"
	"unicode"
	"unicode/utf8"
)


type ErrInFlows struct {
	errs []*ErrLeak
}

func NewErrInFlows() *ErrInFlows {
	e := &ErrInFlows{errs: make([]*ErrLeak, 0)}
	return e
}
func (e *ErrInFlows) Add(err *ErrLeak) {
	for _, errs := range e.errs {
		if errs.Error() == err.Error() {
			return
		}
	}
	e.errs = append(e.errs, err)
}

// Error returns a string of all flows beeing in e.
func (e *ErrInFlows) Error() (s string) {
	for _, err := range e.errs {
		if err != nil {
			s += err.Error()
		}
	}
	return
}

// NumberOfFlows returns the number of taint.ErrLeaks in ErrInFlows
func (e *ErrInFlows) NumberOfFlows() int {
	return len(e.errs)
}

type ErrLeak struct {
	Call ssa.CallCommon
	Args []ssa.Value
	Err  error
}

func (e *ErrLeak) Error() (s string) {
	s = "The function with signature: "
	callCom := e.Call
	if callCom.Signature() != nil {
		s += callCom.Signature().String()
	}
	if callCom.StaticCallee() != nil {
		s += callCom.StaticCallee().Name()
	}
	pos := callCom.Pos()
	s += " is reached by at minimum one tainted argument: \n"

	fset := e.Args[0].Parent().Prog.Fset
	if fset != nil{
		location := fset.File(pos).Line(pos)
		f := fset.File(pos)
		filepath := f.Name()
		fset.File(pos).Name()
		fmt.Print("leak at file:")
		fmt.Printf(" %s:%d \n",filepath,location)
	}

	//for i, arg := range e.Args {
	//	if i > 1 {
	//		s += " | "
	//	}
	//	k := arg.String()
	//
	//	s += k
	//	s += " - " + arg.Name() + " of type: " + arg.Type().String() + " "
	//	//pos := arg.Pos()
	//	if arg.Parent() != nil && arg.Parent().Prog != nil && arg.Parent().Prog.Fset != nil {
	//		fileset := arg.Parent().Prog.Fset
	//		location := fileset.File(pos).Line(pos)
	//		f := fileset.File(pos)
	//		filepath := f.Name()
	//		fileset.File(pos).Name()
	//		fmt.Print("leak at file:")
	//		fmt.Printf(" %s:%d \n",filepath,location)
	//		//s += " at: file:" + filepath + " near to :" + strconv.Itoa(location)
	//	}
	//}
	s += "\n"
	return
}

// NewErrInFlow returns a error of type ErrInFlow.
func NewErrInFlow(c *ssa.CallCommon, a []ssa.Value, e error) error {
	return &ErrLeak{Call: *c, Args: a, Err: e}
}


func getSignature(c ssa.CallCommon) (signature, staticCallee, iSignature string) {
	// [vs: can this signature be an interface here? If yes, do we miss "up-casted" sources?]
	// Get the signatuer and iterate through the sources
	signature = c.Signature().String()
	if c.StaticCallee() != nil {
		staticCallee = c.StaticCallee().String()
	}

	var sigSlice []string
	if types.IsInterface(c.Signature().Underlying()) {
		// Signature for an interface does not contain names for the parameters
		sigI := c.Signature().String()
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

func isSource(c ssa.CallCommon) bool {
	sig, call, iSig := getSignature(c)
	for _, source := range utils.SS.Sources {
		if source.IsInterface() {
			if iSig == source.GetSignature() {
				return true
			}
		}
		if sig == source.GetSignature() {
			if call == source.GetCallee() {
				return true
			}
		}
	}
	return false
}


func isSink(c ssa.CallCommon) bool {
	sig, call, iSig := getSignature(c)
	for _, sink := range utils.SS.Sinks {
		if sink.IsInterface() {
			if iSig == sink.GetSignature() {
				return true
			}
		}
		if sig == sink.GetSignature() {
			if call == sink.GetCallee() {
				return true
			}
		}
	}
	return false
}


func checkAndHandleSourcesAndsinks(c ssa.Instruction, l Lattice, ptr bool) PlainFF {
	// ensure that err is nil because it is later used to distinguish whether a information flow occurs or not.
	var callCom ssa.CallCommon
	switch xType := c.(type) {
	case *ssa.Call:
		callCom = xType.Call
	case *ssa.Defer:
		callCom = xType.Call
	case *ssa.Go:
		callCom = xType.Call
	default:
		return nil
	}
	// Get the lup of the value
	lupVal := l.GetTag(callCom.Value)
	source := isSource(callCom)
	if source {
		return returnTainted
	}
	sink := isSink(callCom)
	err = nil
	if sink {
		err = handleSinkDetection(callCom, l, ptr)
	}

	if err != nil {
		return returnLUPTaint(lupVal)
	}

	return nil
}


func handleSinkDetection(c ssa.CallCommon, l Lattice, ptr bool) error {
	//log.Printf("HandleSinkDetection: for: %s with lattice: %s \n", c.String(), l.String())
	val := c.Value
	var argsErr []ssa.Value
	if l.GetTag(val) == Tainted || l.GetTag(val) == Both {
		argsErr = append(argsErr, val)
	}
	// [vs] Sometimes Args contains Value! Be careful, at least comment?
	// See: https://godoc.org/golang.org/x/tools/go/ssa#Call.Value
	args := c.Args

	for _, arg := range args {
		if l.GetTag(arg) == Tainted || l.GetTag(arg) == Both {
			argsErr = append(argsErr, arg)
		}
	}
	if ptr {
		lptr, ok := l.(*LatticePointer)
		if ok {
			for _, arg := range args {
				valsPtsTo := lptr.GetSSAValMayAlias(arg)
				for _, v := range valsPtsTo {
					if v.Name() == "t2" {
						log.Printf("t2 aliases %s\n", arg.Name())
					}
					if lptr.GetTag(v) == Tainted || lptr.GetTag(v) == Both {
						argsErr = append(argsErr, arg)
					}
				}
			}
		}
	}
	// Handle the case that one parameter is a variable

	if len(argsErr) != 0 {
		log.Printf("new err in flow")
		err = NewErrInFlow(&c, argsErr, nil)
		return err
	}

	return nil
}
