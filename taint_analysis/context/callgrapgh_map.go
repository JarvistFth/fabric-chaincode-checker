package context

import (
	"github.com/emirpasic/gods/maps/hashmap"
	"github.com/op/go-logging"
)
var log = logging.MustGetLogger("Main")

type CallGraphMap *hashmap.Map


func NewCallGraphMap() *hashmap.Map {

	n := hashmap.New()

	return n
}
