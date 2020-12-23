package main

import (
	"errors"
	"log"
	"math"
	"math/rand"
	"strconv"
)

type Putting interface {
	PutState(n int) error
}

type Testobj struct {

}

func main() {
	n := rand.Int()

	log.Printf("%d",n)
	//o := Testobj{}
	//err := o.PutState(n)
	//d := source(n)
	//if err != nil{
	//	log.Fatalf(err.Error())
	//}
	//sink(d)
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