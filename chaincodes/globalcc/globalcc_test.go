package globalcc

import (
	"fmt"
	"testing"
)

func TestHain(t *testing.T) {
	s := &SimpleAsset{}
	stub := NewMockStub("h",s)
	stub.Args = handle("set",[]string{"1","2"})
	stub.MockTransactionStart("1")
	res := s.Invoke(stub)
	stub.MockTransactionEnd("1")
	fmt.Printf("Response Value:【%s】\n", string(res.Payload))
}

func handle(fn string, params []string) [][]byte{
	paramsValue := [][]byte{}
	paramsValue = append(paramsValue, []byte(fn))
	if len(params) > 0 {
		for _, v := range params {
			vv := []byte(v)
			paramsValue = append(paramsValue, vv)
		}
	}
	return paramsValue
}

type MyStub struct {

}