package context

import (
	"chaincode-checker/taint_analysis/logger"
	"github.com/emirpasic/gods/maps/hashmap"
)
var log = logger.GetLogger("./debuglogs/test")

type CallGraphMap *hashmap.Map


func NewCallGraphMap() *hashmap.Map {

	n := hashmap.New()

	return n
}
