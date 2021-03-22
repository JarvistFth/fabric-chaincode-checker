/*
 * Copyright IBM Corp All Rights Reserved
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/hyperledger/fabric/protos/peer"
	"log"
	"time"
)

// SimpleAsset implements a simple chaincode to manage an asset
type SimpleAsset struct {
}

type Tsg struct {
	Time string `json:"time"`
}

// Init is called during chaincode instantiation to initialize any
// data. Note that chaincode upgrade also calls this function to reset
// or to migrate data.
func (t *SimpleAsset) Init(stub shim.ChaincodeStubInterface) peer.Response {
	// Get the args from the transaction proposal
	_,args := stub.GetFunctionAndParameters()
	if len(args) != 2 {
		return shim.Error(fmt.Sprintf("incorrect args, len(args):%d", len(args)))
	}

	// Set up any variables or assets here by calling stub.PutState()

	// We store the key and the value on the ledger
	err := stub.PutState(args[0], []byte(args[1]))
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to create asset: %s", args[0]))
	}
	return shim.Success([]byte(fmt.Sprintf("create key: %s, success",args[0])))
}

// Invoke is called per transaction on the chaincode. Each transaction is
// either a 'get' or a 'set' on the asset created by Init function. The Set
// method may create a new asset by specifying a new key-value pair.
func (t *SimpleAsset) Invoke(stub shim.ChaincodeStubInterface) peer.Response {
	// Extract the function and args from the transaction proposal
	_, args := stub.GetFunctionAndParameters()

	//var result string
	//var err error
	//if fn == "setWithRand" {
	//	var last = rand.Int()
	//	slast := strconv.Itoa(last)
	//	args[1] += slast
	//	result, err = set(stub, args)
	//} else if fn == "get"{ // assume 'get' even if fn is nil
	//	result, err = get(stub, args)
	//}else if fn == "setWithTime"{
	//	var t = time.Now().Format("2006-01-02 15:04:05.999999")
	//	args[1] += t
	//	result, err = set(stub, args)
	//}

	//var last = rand.Int()
	//slast := fmt.Sprintf("%d",last)
	////slast = strconv.Itoa(last)
	//args[1] += slast
	//result, err := set(stub, args)

	tim := time.Now().Format("2006-01-02 15:04:05")
	//a := 1
	//b := &a
	//c := &a
	//d := *b
	//e := *c
	//log.Print(d,e)
	//o := Tsg{Time: tim}
	//ob,_ := json.Marshal(o)
	err := stub.PutState(args[0],[]byte(tim))
	//err = stub.PutState(args[0], ob)
	s := fmt.Sprintf("time: %s, %s", tim,args[0])
	//f, _ := os.Open("test.txt")
	//b := make([]byte,10)
	//f.Read(b)
	//os.OpenFile()
	//exec.Command()
	err = stub.PutState(args[0], []byte(s))

	if err != nil {
		return shim.Error(err.Error())
	}

	// Return the result as success payload
	return shim.Success([]byte("ok"))
}

// Set stores the asset (both key and value) on the ledger. If the key exists,
// it will override the value with the new one
func set(stub shim.ChaincodeStubInterface, args []string) (string, error) {
	if len(args) != 2 {
		return "", fmt.Errorf("Incorrect arguments. Expecting a key and a value")
	}

	err := stub.PutState(args[0], []byte(args[1]))
	if err != nil {
		return "", fmt.Errorf("Failed to set asset: %s", args[0])
	}
	return args[1], nil
}

// Get returns the value of the specified asset key
func get(stub shim.ChaincodeStubInterface, args []string) (string, error) {
	if len(args) != 1 {
		return "", fmt.Errorf("Incorrect arguments. Expecting a key")
	}

	value, err := stub.GetState(args[0])
	if err != nil {
		return "", fmt.Errorf("Failed to get asset: %s with error: %s", args[0], err)
	}
	if value == nil {
		return "", fmt.Errorf("Asset not found: %s", args[0])
	}
	return string(value), nil
}

// main function starts up the chaincode in the container during instantiate
func main() {
	//if err := shim.Start(new(SimpleAsset)); err != nil {
	//	fmt.Printf("Error starting SimpleAsset chaincode: %s", err)
	//}


	s := new(SimpleAsset)
	stub := shim.NewMockStub("SimpleAsset",s)
	stub.GetFunctionAndParameters()
	s.Invoke(stub)
	//TestInvoke(stub)
}

func TestInvoke(stub *shim.MockStub) {
	str := []string{"a","b" }
	CheckInvoke(stub,"set",str)
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