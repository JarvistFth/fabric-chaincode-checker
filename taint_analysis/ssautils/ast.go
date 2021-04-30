package ssautils

import (
	"chaincode-checker/taint_analysis/Errors"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strings"
)


func createAST(filename string) {
	//fileset := token.NewFileSet()
	//root, e := parser.ParseFile(fileset, filename, nil, parser.ParseComments)


}

func checkAst(fset *token.FileSet, astfile *ast.File, pkg types.Info){
	fmt.Println("start ast")
	ast.Inspect(astfile, func(n ast.Node) bool {
		switch stmt := n.(type) {
		case *ast.AssignStmt:
			//fmt.Printf("AssignStmt: %v\n",stmt.Pos())
			for _, expr := range stmt.Rhs {
				if callExpr, ok := expr.(*ast.CallExpr); ok  {
					pos := returnsError(callExpr, &pkg)
					if pos < 0 || pos >= len(stmt.Lhs) {
						//return nil, nil
						continue
					}
					if id, ok := stmt.Lhs[pos].(*ast.Ident); ok && id.Name == "_" {
						reason := Errors.ERR_UNHANDLED_ERROR
						pos := fmt.Sprintf("%v",fset.Position(stmt.Pos()))
						//fmt.Printf("unhandled error here: %v\n",fset.Position(stmt.Pos()))

						Errors.NewErrorMsgOut(reason,pos)

						//return gosec.NewIssue(ctx, n, r.ID(), r.What, r.Severity, r.Confidence), nil
					}

					//isrw,functype := checkReadYourWrite(callExpr,&pkg)
					//if isrw{
					//	pos := fmt.Sprintf("%v",fset.Position(stmt.Pos()))
					//	fmt.Println(functype, pos)
					//}


				}
			}
			//return true
		case *ast.ExprStmt:
			if callExpr, ok := stmt.X.(*ast.CallExpr); ok  {
				pos := returnsError(callExpr, &pkg)
				if pos >= 0 {
					reason := Errors.ERR_UNHANDLED_ERROR
					pos := fmt.Sprintf("%v",fset.Position(stmt.Pos()))
					//fmt.Printf("unhandled error here: %v\n",fset.Position(stmt.Pos()))

					Errors.NewErrorMsgOut(reason,pos)
				}
			}
			//return true
		}
		return true
	})



}

func returnsPointer(callExpr *ast.CallExpr, pkginfo *types.Info) int{
	if tv := pkginfo.TypeOf(callExpr); tv != nil {
		switch t := tv.(type) {
		case *types.Tuple:
			for pos := 0; pos < t.Len(); pos++ {
				variable := t.At(pos)
				if variable != nil  {
					_,ok := variable.Type().(*types.Pointer)
					if ok {
						return pos
					}
				}
			}
		case *types.Pointer:
			return 0
		}
	}else{

		//fmt.Printf("fset on line %v:\n",fset.Position(callExpr.Pos()))

	}
	return -1
}

func returnsError(callExpr *ast.CallExpr, pkginfo *types.Info) int {
	if tv := pkginfo.TypeOf(callExpr); tv != nil {
		switch t := tv.(type) {
		case *types.Tuple:
			for pos := 0; pos < t.Len(); pos++ {
				variable := t.At(pos)
				if variable != nil && variable.Type().String() == "error" {
					return pos
				}
			}
		case *types.Named:
			if t.String() == "error" {
				return 0
			}
		}
	}else{

		//fmt.Printf("fset on line %v:\n",fset.Position(callExpr.Pos()))

	}
	return -1
}

func checkReadYourWrite(callExpr *ast.CallExpr, pkginfo *types.Info) (bool,string){

	function,ok := callExpr.Fun.(*ast.SelectorExpr)
	if ok{
		if function.Sel.Name == "PutState"{
			id,ok := function.X.(*ast.Ident)
			if ok{
				//objName := id.Obj

				objtype := pkginfo.ObjectOf(id).Type().String()
				relativepkgs := strings.Split(objtype,"/")
				objname := relativepkgs[len(relativepkgs) - 1]
				fmt.Println("write:",objname)
			}
			args := callExpr.Args
			switch exprType := args[0].(type) {
			case *ast.IndexExpr:
				id,ok := exprType.X.(*ast.Ident)
				if ok{
					fmt.Println("putState key:",id.Name)
				}
				break
			case *ast.Ident:
				keyname := exprType.Name
				fmt.Println("putState key:",keyname)
				break

			}



			return true,"writefunc"
		}else if function.Sel.Name == "GetState"{
			id,ok := function.X.(*ast.Ident)
			if ok{
				objName := id.Obj.Name
				fmt.Println("read func:",objName)
			}
			return true,"readfunc"
		}else{
			return false,""
		}
	}
	return false,""


}