package chaincodes

import (
	"chaincode-checker/chaincodes/timerandom"
	"fmt"
	"github.com/hyperledger/fabric/core/chaincode/shim"
)

func main() {
	err := shim.Start(new(timerandom.SimpleAsset))
	if err != nil {
		fmt.Printf("Error starting BsnChainCode: %s", err)
	}
}
