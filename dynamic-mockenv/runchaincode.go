package dynamic_mockenv

import (
	"chaincode-checker/chaincodes/timerandom"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	"sync"
)

var once sync.Once
var mockstub *shim.MockStub
func newMockStub() *shim.MockStub {
	once.Do(func() {
		bsnChainCode := new(timerandom.SimpleAsset)
		mockstub = shim.NewMockStub("bsnChainCode", bsnChainCode)
	})
	return mockstub
}