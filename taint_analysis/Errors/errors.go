package Errors

import (
	"chaincode-checker/taint_analysis/logger"
	"encoding/json"
	"fmt"
	"github.com/emirpasic/gods/sets/hashset"
	"go/token"
	"golang.org/x/tools/go/ssa"
	"io"
	"os"
)

//type ErrorMessages []ErrorMsgOut
var log = logger.GetLogger("./debuglogs/test")
var outputfile *os.File
var ErrorMsgPool *ErrorMsgOuts

const (
	ERR_TIMESTAMP = "use timestamp here"
	ERR_GLOBALVALUE = "use global value here"
	ERR_RANDOM = "use random value here"

	ERR_FILE         = "OUTSIDE_FILE_OPEN"
	ERR_CMD          = "OUTSIDE_COMMAND_EXEC"
	ERR_EXTERNAL_LIB = "USE_EXTERNAL_LIB"

	ERR_GOROUTINE = "USE_GOROUTINE"

	ERR_CROSSCHANNEL = "CROSS_CHANNEL"
	ERR_READYOURWRITE = "READ_AFTER_WRITE"

	ERR_UNHANDLED_ERROR = "UNHANDLED_ERROR"

	WARNING_READ_FUNCTION = "READ_STATE_FUNCTION"
	WARNING_WRITE_FUNCTION = "WRITE_STATE_FUNCTION"
	ERROR_LEVEL = "ERROR"
	WARNING_LEVEL = "WARNING"

)



var levelMap map[string]string

func InitLevelMap(){
	levelMap = make(map[string]string)
	levelMap[ERR_TIMESTAMP] = ERROR_LEVEL
	levelMap[ERR_GLOBALVALUE] = ERROR_LEVEL
	levelMap[ERR_GOROUTINE] = WARNING_LEVEL
	levelMap[ERR_CMD] = WARNING_LEVEL
	levelMap[ERR_CROSSCHANNEL] = WARNING_LEVEL
	levelMap[ERR_FILE] = WARNING_LEVEL
	levelMap[ERR_READYOURWRITE] = WARNING_LEVEL
	levelMap[ERR_RANDOM] = WARNING_LEVEL
	levelMap[ERR_EXTERNAL_LIB] = WARNING_LEVEL
	levelMap[ERR_UNHANDLED_ERROR] = WARNING_LEVEL
	var err error
	outputfile,err = os.OpenFile("result.txt",os.O_CREATE|os.O_APPEND|os.O_WRONLY,0666)
	ErrorMsgPool = new (ErrorMsgOuts)
	if err != nil{
		fmt.Println(err.Error())
	}
}

type ErrorMessage struct {
	SSAInstr ssa.Instruction
	Call     ssa.CallCommon
	Args     []ssa.Value
	Msg      string
	Token	 token.Pos
}

type ErrorMsgOut struct {
	Pos   string `json:"position"`
	Level string `json:"level"`
	Rules  string `json:"rules"`
}
type ErrorMsgOuts struct {
	Outs []ErrorMsgOut `json:"results"`
}

var ErrSet *hashset.Set

func NewErrSet(){
	ErrSet = hashset.New()
}

func NewErrMessage(ssaval ssa.Instruction, callcommon ssa.CallCommon, msg string) {

	ret := ErrorMessage{
		SSAInstr: ssaval,
		Call:     callcommon,
		Args:     callcommon.Args,
		Msg:      msg,
		Token:	  ssaval.Pos(),
	}

	if ErrSet.Contains(ssaval.String()+msg){
		return
	}

	ErrSet.Add(ssaval.String()+msg)
	out := ret.toOut()
	ErrorMsgPool.Outs = append(ErrorMsgPool.Outs,out)
	return
}

func NewErrorMsgOut(rules, pos string,) ErrorMsgOut {
	ret := ErrorMsgOut{
		Pos:   pos,
		Level: levelMap[rules],
		Rules: rules,
	}
	ErrorMsgPool.Outs = append(ErrorMsgPool.Outs,ret)
	return ret
}


func(m ErrorMsgOuts) Empty() bool{
	return len(m.Outs) <= 0
}

func (e ErrorMessage) toOut() ErrorMsgOut{

	pos := e.Call.Pos()
	fset := e.SSAInstr.Parent().Prog.Fset
	var dpos string
	var reason string
	if fset != nil{
		location := fset.File(pos).Line(pos)
		f := fset.File(pos)
		filepath := f.Name()
		fset.File(pos).Name()
		dpos = fmt.Sprintf("file: %s:%d",filepath,location)
		reason = e.Msg
		//return fmt.Sprintf("function with signature: %s\nleak at file: %s:%d, for reason:%s\n", s,filepath,location,e.Msg)
	}

	ret := ErrorMsgOut{
		Pos:   dpos,
		Level: levelMap[reason],
		Rules: reason,
	}
	return ret
}

func(e ErrorMessage) String() string {
	var s string
	callCom := e.Call
	var fset *token.FileSet
	if callCom.StaticCallee() != nil {
		s += callCom.StaticCallee().Name() + "-"

	}else{
		s += callCom.Method.FullName() + "-"
	}
	fset = e.SSAInstr.Parent().Prog.Fset
	if callCom.Signature() != nil {
		s += callCom.Signature().String()
	}


	pos := callCom.Pos()
	log.Debugf("call fail:%s", e.Call.String())
	if fset != nil{
		location := fset.File(pos).Line(pos)
		f := fset.File(pos)
		filepath := f.Name()
		fset.File(pos).Name()
		return fmt.Sprintf("function with signature: %s\nleak at file: %s:%d, for reason:%s\n", s,filepath,location, e.Msg)
	}
	return fmt.Sprintf("function with signature: %s, leak with nil fset, for reason:%s\n", s, e.Msg)
}



func (m ErrorMsgOuts) Output() {
	//jsonres,err := json.Marshal(o)
	//ioutil.WriteFile()
	//fmt.Fprintf(outputfile.)

	jsonres,err := json.MarshalIndent(m,"","\t")
	if err != nil{
		fmt.Println(err.Error())
	}
	_, err = io.WriteString(outputfile, string(jsonres))
	if err != nil{
		fmt.Println(err.Error())
	}
}


