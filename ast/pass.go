package ast

import (

	"go/ast"
	"go/parser"

	"go/token"
	"golang.org/x/tools/go/cfg"
	"log"

)

func FindRand(filename string)  {
	fset := token.NewFileSet()
	f,err := parser.ParseFile(fset,filename,nil,parser.ParseComments)
	if err != nil{
		log.Fatal(err.Error())
	}

	//check global var
	//for _,obj := range f.Scope.Objects{
	//	if fmt.Sprint(obj.Kind) == "var"{
	//		fmt.Printf("statement found on line %v:\n", fset.Position(obj.Pos()))
	//	}
	//}


	ast.Inspect(f, func(node ast.Node) bool {

		//if callexpr, ok := node.(*ast.CallExpr);ok{
			//if callfunc,ok := ret.Fun.(* ast.SelectorExpr);ok{
			//	if fmt.Sprint(callfunc.X) == "rand"{
			//		fmt.Printf("statement found on line %v:\n", fset.Position(ret.Pos()))
			//		printer.Fprint(os.Stdout, fset, ret)
			//		fmt.Printf("\n")
			//		return true
			//	}
			//}
		//}
		//if declstmt ok :=



		//x,ok := node.(*ast.UnaryExpr)
		//if ok {
		//	fmt.Println(x.Op,x.OpPos)
		//}
		return true
	})

}

func TryCFG(filename string) {
	fset := token.NewFileSet()
	f,err := parser.ParseFile(fset,filename,nil,parser.ParseComments)
	if err != nil{
		log.Fatal(err.Error())
	}
	for _,decl := range f.Decls{
		if decl,ok := decl.(*ast.FuncDecl);ok{
			g := cfg.New(decl.Body,mayReturn)
			for _,b := range g.Blocks{
				if !b.Live{

				}
			}
			log.Printf("cfg: %s,%s", decl.Name, g.Format(fset))
		}
	}

}

func mayReturn(call *ast.CallExpr)bool  {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name != "panic"
	case *ast.SelectorExpr:
		return fun.Sel.Name != "Fatal"
	}
	return true
}

