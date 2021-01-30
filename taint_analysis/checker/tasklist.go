package checker

import (
	"chaincode-checker/taint_analysis/context"
	"container/list"
)

type TaskList struct {
	//map[]
	list *list.List

}

func NewTaskList() *TaskList{
	t := &TaskList{}
	t.list = list.New()
	return t
}

func (l *TaskList) PushFront(value *context.InstructionContext) {
 	l.list.PushFront(value)
}

func (l *TaskList) PushBack(value *context.InstructionContext) {
	l.list.PushBack(value)
}

func (l *TaskList) RemoveFront() *context.InstructionContext {
	ret := l.list.Front()
	if ret != nil{
		l.list.Remove(ret)
		return ret.Value.(*context.InstructionContext)
	}
	return nil
}

func (l *TaskList) PopBack() *context.InstructionContext {
	ret := l.list.Back()
	if ret != nil{
		l.list.Remove(ret)
		return ret.Value.(*context.InstructionContext)
	}
	return nil
}

func (l *TaskList) Len() int  {
	return l.list.Len()
}

func (l *TaskList) Empty() bool {
	return l.list.Len() == 0
}
