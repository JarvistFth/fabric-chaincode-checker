package main

import (
	"chaincode-checker/chaincodes/globalcc"
	"fmt"
	"github.com/hyperledger/fabric/core/chaincode/shim"
)

func main() {
	err := shim.Start(new(globalcc.SimpleAsset))
	if err != nil {
		fmt.Printf("Error starting BsnChainCode: %s", err)
	}
}
