package checker

import (
	"chaincode-checker/go-taint/context"
	"fmt"
)

type TaskList struct {
	taskMap map[*context.InstructionContext]bool
	order []*context.InstructionContext
	MaxElement int


}

func NewTaskList() *TaskList {
	m := make(map[*context.InstructionContext]bool)
	o := make([]*context.InstructionContext,0)
	ret := &TaskList{
		taskMap: m,
		order:   o,
	}
	return ret
}

func (l *TaskList) GetFirstCCS() *context.InstructionContext {
	for i:= 0 ; i < len(l.order); i++{
		if ok := l.taskMap[l.order[i]];ok{
			return l.order[i]
		}
	}
	return nil
}

func (l *TaskList) RemoveFirstCCS() *context.InstructionContext {
	var ret *context.InstructionContext = nil
	log.Debugf("tasklist map len: %d",len(l.taskMap))
	for i:= 0 ; i<len(l.order);i++{
		if ok := l.taskMap[l.order[i]];ok{
			ret = l.order[i]
			delete(l.taskMap,l.order[i])
			l.order = l.order[i:]
			return ret
		}
	}

	return ret
}

func (l *TaskList) Empty() bool {
	return len(l.taskMap) == 0
}

func (l *TaskList) Add(c *context.InstructionContext) {

	log.Debugf("add contextCallSite: %s", c.GetNode().String())

	_, ok := l.taskMap[c]

	// c as entry not exist, create it
	if !ok{
		l.order = append(l.order,c)
		l.taskMap[c] = true
	}

	if l.MaxElement < len(l.taskMap){
		l.MaxElement = len(l.taskMap)
	}
}

func (l *TaskList) Len() int {
	return len(l.taskMap)
}

func (l *TaskList) String() string {
	var ret string
	for i:= 0 ; i< len(l.order); i++{
		if ok := l.taskMap[l.order[i]];ok{
			ret += fmt.Sprintf("[ %d : %s ] ",l.order[i].Id, l.order[i].GetNode().String())
		}
	}
	return ret
}
