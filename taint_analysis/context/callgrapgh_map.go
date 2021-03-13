package context

import (
	"github.com/emirpasic/gods/maps/hashmap"
)

type CallGraphMap *hashmap.Map


func NewCallGraphMap() *hashmap.Map {

	n := hashmap.New()

	return n
}
