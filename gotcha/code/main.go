package code

import (
	"errors"
	"log"
	"math"
	"math/rand"
	"strconv"
)

var k = 1

type Putting interface {
	PutState(n int) error
}

type Testobj struct {

}

func main() {
	n := rand.Int()
	//k := source(n)
	log.Printf("%d",n+k)
}

func (o Testobj)PutState(n int) error {
	if n > math.MaxInt64{
		return errors.New("overflow")
	}
	s := strconv.Itoa(n)
	log.Printf(s)
	return nil
}

func source(n int) int {
	return n+1
}

func sink(n int){
	log.Printf("%d",n)
}