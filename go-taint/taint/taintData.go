package taint

type TaintData struct {
	Sig    string
	Callee string

	IsGlobal bool
	IsInterface bool
	Name string
}

func NewTaintData(sig,callee,name string, isglobal,isinterface bool) *TaintData {
	td := &TaintData{
		Sig:         sig,
		Callee:      callee,
		IsGlobal:    isglobal,
		IsInterface: isinterface,
		Name:        name,
	}
	return td
}


