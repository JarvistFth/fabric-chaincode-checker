package flows

import (
	"fmt"
	"golang.org/x/tools/go/ssa"
)

type ErrInFlows struct {
	errs []*ErrLeak
}

func NewErrInFlows() *ErrInFlows {
	e := &ErrInFlows{errs: make([]*ErrLeak, 0)}
	return e
}
func (e *ErrInFlows) add(err *ErrLeak) {
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

func (e ErrLeak) Error() (s string) {
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
	return ErrLeak{Call: *c, Args: a, Err: e}
}
