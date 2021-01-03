package main

import (
	"log"
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
	l := k + 1
	//k := source(n)
	o := &Testobj{}
	if n % 2 == 0{
		_ = o.PutState(n)
	}else{
		_ = o.PutState(n + 1)
	}


	log.Printf("%d",n+l)
	//_ = o.PutState(l)
}

func (o *Testobj)PutState(n int) error {
	//if n > math.MaxInt64{
	//	return errors.New("overflow")
	//}
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