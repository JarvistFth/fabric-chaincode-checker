package context

import (
	sll "github.com/emirpasic/gods/lists/singlylinkedlist"
)

type Queue struct{
	l *sll.List
}

func NewQueue() *Queue{
	q := &Queue{l: sll.New()}
	return q
}

func (q *Queue) Push(val interface{})  {
	q.l.Add(val)
}

func (q *Queue) Pop() interface{} {
	ret,_ := q.l.Get(0)
	q.l.Remove(0)
	return ret
}

func (q *Queue) Front() interface{} {
	ret,_ := q.l.Get(0)
	return ret
}

func (q *Queue) Empty() bool {
	return q.l.Empty()
}

func (q *Queue) Size() int {
	return q.l.Size()
}





