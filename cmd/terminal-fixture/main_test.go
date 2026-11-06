// File main_test.go pins the fixture's validated-address handoff to both roles.
package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// TestFixtureRolesUseValidatedEndpoint guards the DNS-rebinding boundary without
// issuing DNS queries or opening sockets: neither role may resolve the original
// flag again after main has validated its loopback TCP endpoint.
func TestFixtureRolesUseValidatedEndpoint(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		role, ok := call.Fun.(*ast.Ident)
		if !ok || role.Name != "serve" && role.Name != "call" {
			return true
		}
		checked++
		if len(call.Args) < 2 {
			t.Errorf("%s lacks endpoint argument", role.Name)
			return true
		}
		address, ok := call.Args[1].(*ast.CallExpr)
		if !ok || len(address.Args) != 0 {
			t.Errorf("%s does not use validated endpoint.String()", role.Name)
			return true
		}
		method, ok := address.Fun.(*ast.SelectorExpr)
		if !ok {
			t.Errorf("%s does not use validated endpoint.String()", role.Name)
			return true
		}
		endpoint, ok := method.X.(*ast.Ident)
		if !ok || endpoint.Name != "endpoint" || method.Sel.Name != "String" {
			t.Errorf("%s re-resolves unvalidated address input", role.Name)
		}
		return true
	})
	if checked != 2 {
		t.Fatalf("checked %d role handoffs, want server and client", checked)
	}
}
