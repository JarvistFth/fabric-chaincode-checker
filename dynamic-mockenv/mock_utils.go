
package dynamic_mockenv


import (
	"fmt"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	"log"
)


func CheckInit(stub *shim.MockStub, args [][]byte) {
	res := stub.MockInit("1", args)
	if res.Status != shim.OK {
		log.Fatalf("init failed: %s", res.Message)
	}
}


func CheckQuery(stub *shim.MockStub, fn string, params []string) {
	checkHandle(stub, fn, params)
}


func CheckInvoke( stub *shim.MockStub, fn string, params []string) {
	checkHandle( stub, fn, params)
}

func checkHandle( stub *shim.MockStub, fn string, params []string) {
	paramsValue := [][]byte{}
	paramsValue = append(paramsValue, []byte(fn))
	if len(params) > 0 {
		for _, v := range params {
			vv := []byte(v)
			paramsValue = append(paramsValue, vv)
		}
	}

	res := stub.MockInvoke("1", paramsValue)

	fmt.Printf("【%s】 Response Status:【%d】\n", fn, res.Status)

	if res.Status != shim.OK {
		log.Fatalf("【%s】 failed:%s\n", fn, res.Message)
	}
	fmt.Printf("【%s】 Response Value:【%s】\n", fn, string(res.Payload))
}

