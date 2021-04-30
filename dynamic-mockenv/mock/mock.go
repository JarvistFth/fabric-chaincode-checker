package mock

import (
	"chaincode-checker/chaincodes/globalcc"
	"fmt"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	"log"
	"testing"
)

func TestMock(t *testing.T)  {
	Fuzz([]byte("testget"))
}
//
func Fuzz(data []byte)int{
	var fn string
	fn = "set"
	cc := new(globalcc.SimpleAsset)

	stub := shim.NewMockStub("cc",cc)
	stub.MockInit("u",[][]byte{data,data})
	res := stub.MockInvoke("u",[][]byte{[]byte(fn),data})
	if res.Status != shim.OK{
		log.Printf("【%s】 failed:%s\n", fn, res.Message)
		return -1
	}
	fmt.Printf("【%s】 Response Value:【%s】\n", fn, string(res.Payload))
	stub.PutState()
	return 0
}

