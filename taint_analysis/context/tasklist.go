package context

import (
	dll "github.com/emirpasic/gods/lists/doublylinkedlist"
)

type TaskList struct {
	//map[]
	list *dll.List

}

func NewTaskList() *TaskList {
	t := &TaskList{list: dll.New()}
	return t
}

func (l *TaskList) PushBack(value *InstructionContext) {
	l.list.Add(value)
}

func (l *TaskList) RemoveFront() *InstructionContext {
	ret,found := l.list.Get(0)
	if found{
		l.list.Remove(0)
		return ret.(*InstructionContext)
	}
	return nil
}


func (l *TaskList) Len() int  {
	return l.list.Size()
}

func (l *TaskList) Empty() bool {
	return l.list.Empty()
}

func (l *TaskList) String() string {
	var ret string

	instrs := l.list.Values()

	for _,val := range instrs{
		instrs := val.(*InstructionContext)
		ret +=  instrs.String() + " \n"
	}
	return ret
}
