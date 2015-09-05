package frontend

import (
	"fmt"
	"github.com/rfjakob/cluefs/lib/cluefs"
)

type Node struct {
	*cluefs.Node
}

func NewNode(parent string, name string, fs *FS) *Node {
	fmt.Printf("NewNode\n")
	return &Node{
		Node: cluefs.NewNode(parent, name, fs.ClueFS),
	}
}
