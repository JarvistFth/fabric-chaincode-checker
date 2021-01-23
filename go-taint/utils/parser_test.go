package utils

import (
	"fmt"
	"testing"
)

func TestParseSourceAndSinkFile(t *testing.T) {


	ParseSourceAndSinkFile("sourceandsink.json")

	fmt.Println(SS.String())
	fmt.Println(FunctionConfig.SDKFunctionString())
}
