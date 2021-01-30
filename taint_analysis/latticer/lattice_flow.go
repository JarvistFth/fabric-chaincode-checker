package latticer

var err error

func returnID(currentValue LatticeTag) (LatticeTag,error) {
	return currentValue,nil
}

func returnUntainted(currentValue LatticeTag) (LatticeTag,error) {
	return Untainted,nil
}

func returnTainted(currentValue LatticeTag) (LatticeTag,error) {
	return Tainted,nil
}

func returnLUP(lupVal LatticeTag) func (LatticeTag) (LatticeTag,error) {
	return func (currentValue LatticeTag) (LatticeTag,error){
		return currentValue.LeastUpperBound(lupVal),nil
	}
}

// returnLUPTaint is similar to returnLUP.
// In contrast to returnLUP, returnLUPTaint can handle error messages.
// An information flow is packed into the ErrInFlow struct which implements the error interface.
func returnLUPTaint (lupVal LatticeTag) func (LatticeTag) (LatticeTag,error) {
	return func (currentValue LatticeTag) (LatticeTag,error) {
		tempVal := currentValue.LeastUpperBound(lupVal)
		if err != nil{
			return tempVal,err
		}
		return tempVal,nil

	}
}

func returnError(currentValue LatticeTag) (LatticeTag, error) {
	return currentValue, err
}

