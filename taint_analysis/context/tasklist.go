package context

import (
	"container/list"
)

type TaskList struct {
	//map[]
	list *list.List

}

func NewTaskList() *TaskList {
	t := &TaskList{}
	t.list = list.New()
	return t
}

func (l *TaskList) PushFront(value *InstructionContext) {
 	l.list.PushFront(value)
}

func (l *TaskList) PushBack(value *InstructionContext) {
	l.list.PushBack(value)
}

func (l *TaskList) RemoveFront() *InstructionContext {
	ret := l.list.Front()
	if ret != nil{
		l.list.Remove(ret)
		return ret.Value.(*InstructionContext)
	}
	return nil
}

func (l *TaskList) PopBack() *InstructionContext {
	ret := l.list.Back()
	if ret != nil{
		l.list.Remove(ret)
		return ret.Value.(*InstructionContext)
	}
	return nil
}

func (l *TaskList) Len() int  {
	return l.list.Len()
}

func (l *TaskList) Empty() bool {
	return l.list.Len() == 0
}
