package mockutil

import (
	"chaincode-checker/chaincodes/globalcc"
	"fmt"
	"github.com/brahma-adshonor/gohook"
	shim "github.com/hyperledger/fabric/core/chaincode/shim"
	"reflect"
	"testing"
)
type bytesArray [][]byte



type CCProxy struct {
	cc shim.Chaincode
}

type StubProxy struct {
	st shim.ChaincodeStubInterface
}

func GetStubProxy(stub shim.ChaincodeStubInterface) *StubProxy {
	return &StubProxy{st: stub}
}

//go:noinline
func out(format string, a ...interface{}){
	fmt.Printf(format,a...)
}

func (p *StubProxy) PutState(key string, value []byte) {
	p.st.PutState(key,value)
	//val := p.st.State[key]
}

//go:noinline
func MyPutState(stub *MockStub,key string, value []byte) error{
	out("start putstate\n")
	After(stub,key,value)
	return nil
}

//go:noinline
func After(stub *MockStub,key string, value []byte)error {
	err := stub.PutState(key,value)
	out("end\n")
	return err
}

//go:noinline
func StringToBytesArray(fn string, params ...string) [][]byte{
	var ret [][]byte
	ret = append(ret, []byte(fn))
	if len(params) > 0 {
		for _, v := range params {
			vv := []byte(v)
			ret = append(ret, vv)
		}
	}
	return ret
}

//go:noinline
func TestHook(t *testing.T){
	cc := new(globalcc.SimpleAsset)
	stub := NewMockStub("cc",cc)
	target := reflect.TypeOf(stub)
	m, ok := target.MethodByName("PutState")
	if ok{
		//fmt.Println(m.Func.String())
		//fmt.Println(target)
	}
	v:=reflect.ValueOf(MyPutState)
	//out("hook:%s\n",v.Type().String())
	//out("method:%s\n",m.Func.Type().String())
	if v.Type() == m.Func.Type(){
		out("type equal\n")
	}
	out("start hook\n")
	err := gohook.HookMethod(stub,"PutState",MyPutState,After)
	if err != nil{
		panic(err.Error())
	}
	out("end hook\n")
	value := StringToBytesArray("set","1","2")
	//stub.MockInit("u", value)
	out("start invoke\n")
	res := stub.MockInvoke("u", value)
	value = StringToBytesArray("get","1","2")
	res = stub.MockInvoke("u2",value)
	fmt.Println(res.String())
}

//go:noinline
func now(){
	out("now\n")
}
//go:noinline
func before(){
	out("before\n")
	after()
}
//go:noinline
func after() {
	//out("after\n")
}

func TestNow(t *testing.T){
	now()

	out("start hook\n")
	gohook.Hook(now,before,after)
	out("end hook\n")

	now()

}

func TestProxy(t *testing.T){
	hookFunc()


}

//go:noinline
func foo1(v1 int, v2 string) int {
	fmt.Printf("foo1:%d(%s)\n", v1, v2)
	return v1 + 42
}

func foo2(v1 int, v2 string) int {
	fmt.Printf("foo2:%d(%s)\n", v1, v2)
	v1 = foo3(100, "not calling foo3")
	return v1 + 4200
}

//go:noinline
func foo3(v1 int, v2 string) int {
	fmt.Printf("foo3:%d(%s)\n", v1, v2)
	return v1 + 10000
}

func hookFunc() {
	ret1 := foo1(23, "miliao for foo1 before hook")

	err := gohook.Hook(foo1, foo2, foo3)

	//foo1:23(miliao for foo1 before hook)
	//hook done
	//foo2:23(miliao for foo1 after hook)
	//foo1:100(not calling foo3)
	//r1:65, r2:4342

	//foo1:23(miliao for foo1 before hook)
	//hook done
	//foo2:23(miliao for foo1 after hook)
	//foo3:100(not calling foo3)
	//r1:65, r2:14300

	//err := gohook.Hook(foo1, foo2, nil)

	fmt.Printf("hook done\n")
	if err != nil {
		fmt.Printf("err:%s\n", err.Error())
		return
	}

	ret2 := foo1(23, "miliao for foo1 after hook")

	fmt.Printf("r1:%d, r2:%d\n", ret1, ret2)
}
