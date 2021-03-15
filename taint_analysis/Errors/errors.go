package Errors

import (
	"chaincode-checker/taint_analysis/logger"
	"fmt"
	"golang.org/x/tools/go/ssa"
)

type ErrorMessages []ErrorMessage
var  ErrMsgPool ErrorMessages
var log = logger.GetLogger("./debuglogs/test")

const (
	USE_TIMESTAMP = "use timestamp here"
	USE_GLOBALVALUE = "use global value here"

	USE_GOROUTINE = "use go routine here"
)

type ErrorMessage struct {
	Call ssa.CallCommon
	Args []ssa.Value
	Msg	 string
}

func NewErrMessage(callcommon ssa.CallCommon, msg string) ErrorMessage {
	ret := ErrorMessage{
		Call: callcommon,
		Args: callcommon.Args,
		Msg:  msg,
	}
	ErrMsgPool = append(ErrMsgPool,ret)
	return ret
}

func NewErrMessages() ErrorMessages {
	return make([]ErrorMessage,0)
}

func(m ErrorMessages) Empty() bool{
	return len(ErrMsgPool) <= 0
}

func(e ErrorMessage) String() string {
	var s string
	callCom := e.Call
	if callCom.StaticCallee() != nil {
		s += callCom.StaticCallee().Name() + "-"
	}else{
		s += callCom.Method.FullName() + "-"
	}

	if callCom.Signature() != nil {
		s += callCom.Signature().String()
	}


	pos := callCom.Pos()

	fset := e.Args[0].Parent().Prog.Fset
	if fset != nil{
		location := fset.File(pos).Line(pos)
		f := fset.File(pos)
		filepath := f.Name()
		fset.File(pos).Name()
		return fmt.Sprintf("function with signature: %s\nleak at file: %s:%d, for reason:%s\n", s,filepath,location,e.Msg)
	}
	return fmt.Sprintf("function with signature: %s, leak with nil fset, for reason:%s\n", s,e.Msg)
}

func (m ErrorMessages) String() (str string) {
	for _,v := range m {
		str += v.String()
	}
	return str
}



