package shim

type Putting interface {
	PutState(n int) error
}
