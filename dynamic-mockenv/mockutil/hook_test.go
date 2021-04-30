package mockutil

import (
	"fmt"
	"github.com/brahma-adshonor/gohook"
	"testing"
)

type CC interface {
	Invoke(b Behavior)error
}

type MyCC struct {

}

func (c *MyCC) Invoke(b Behavior) error {
	fmt.Println("invoke here")
	b.Play()
	return nil
}

type Behavior interface {
	Play() error
}
type Base struct {
	b string
	cc CC
}

type Sub struct {
	s string
	cc CC
}

//go:noinline
func (b *Base) Start() error{
	fmt.Println("start base")
	b.cc.Invoke(b)
	return nil
}

func (b *Base) Play()error  {
	fmt.Println("base Play")
	return nil
}
//go:noinline
func (s *Sub) Play() error{
	fmt.Println("sub Play")
	return nil

}

//go:noinline
func PlayHook(b *Base) error {
	fmt.Println("hook Play function")
	return nil
}



func TestHook1(t *testing.T) {
	c := &MyCC{}
	base := &Base{b: "base",cc: c}
	//sub := &Sub{s: "sub"}

	out("before hook\n")
	base.Start()

	out("start hook\n")

	//gohook.HookMethod(c,"Invoke", PlayHook,nil)
	gohook.HookMethod(base,"Play",PlayHook,nil)
	out("end hook\n")
	base.Start()


}