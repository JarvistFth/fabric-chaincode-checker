package checker

import "testing"

var ssf = "../../config/sourceandsink.json"
var path = "chaincode-checker"
var allpkg = false
var ptr = true
var pkgs = ""
var src = "../../chaincodes/timerandom/timerandomcc.go"

func TestNewChecker(t *testing.T) {
	//NewChecker(path,[]string{src},ssf,allpkg, pkgs, ptr)
	log.Info("new checker end")
}
