package checker

import (
	"chaincode-checker/go-taint/context"
	"fmt"
)

type TaskList struct {
	taskMap map[*context.ContextCallSuite]bool
	order []*context.ContextCallSuite
	MaxElement int


}

func NewTaskList() *TaskList {
	m := make(map[*context.ContextCallSuite]bool)
	o := make([]*context.ContextCallSuite,0)
	ret := &TaskList{
		taskMap: m,
		order:   o,
	}
	return ret
}

func (l *TaskList) GetFirstCCS() *context.ContextCallSuite {
	for i:= 0 ; i < len(l.order); i++{
		if ok := l.taskMap[l.order[i]];ok{
			return l.order[i]
		}
	}
	return nil
}

func (l *TaskList) RemoveFirstCCS() *context.ContextCallSuite {
	var ret *context.ContextCallSuite = nil
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

func (l *TaskList) Add(c *context.ContextCallSuite) {
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
