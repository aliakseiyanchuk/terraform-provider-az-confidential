package model

import (
	"fmt"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
)

type TerraformFieldExpression[T any] struct {
	Value      T
	IsNil      bool
	isDefined  bool
	Mapper     core.Mapper[T, string]
	Expression string
	Include    bool
}

func (expr *TerraformFieldExpression[T]) SetValue(v T) {
	expr.Value = v
	expr.IsNil = false
	expr.isDefined = true
	expr.Expression = ""
}

func (expr *TerraformFieldExpression[T]) WithValue(v T) TerraformFieldExpression[T] {
	expr.SetValue(v)
	return *expr
}

func (expr *TerraformFieldExpression[T]) SetExpression(e string) {
	expr.IsNil = false
	expr.isDefined = true
	expr.Expression = e
}

func (expr *TerraformFieldExpression[T]) WithExpression(e string) TerraformFieldExpression[T] {
	expr.SetExpression(e)
	return *expr
}

func (expr *TerraformFieldExpression[T]) SetNil() {
	expr.IsNil = true
	expr.isDefined = true
	expr.Expression = ""
}

func (expr *TerraformFieldExpression[T]) WithNil() TerraformFieldExpression[T] {
	expr.SetNil()
	return *expr
}

func (expr *TerraformFieldExpression[T]) IsIncluded() bool {
	return !expr.Include
}

func (expr *TerraformFieldExpression[T]) IsDefined() bool {
	return expr.isDefined
}

func (expr *TerraformFieldExpression[T]) TerraformExpression() string {
	if expr.IsNil {
		return "null"
	}

	if len(expr.Expression) > 0 {
		return expr.Expression
	}

	if expr.Mapper == nil {
		return fmt.Sprint(expr.Value)
	} else {
		return expr.Mapper(expr.Value)
	}
}

func NewStringTerraformFieldExpression() TerraformFieldExpression[string] {
	rv := TerraformFieldExpression[string]{
		IsNil:     true,
		isDefined: false,
		Mapper:    func(s string) string { return fmt.Sprintf("\"%s\"", s) },
	}
	return rv
}

func NewStringTerraformFieldHeredocExpression() TerraformFieldExpression[string] {
	rv := TerraformFieldExpression[string]{
		IsNil:     true,
		isDefined: false,
		Mapper:    func(s string) string { return s },
	}
	return rv
}

func NewStringTerraformFieldExpressionWithValue(v string) TerraformFieldExpression[string] {
	rv := NewStringTerraformFieldExpression()
	rv.SetValue(v)
	return rv
}

func NewStringTerraformFieldExpressionWithExpr(v string) TerraformFieldExpression[string] {
	rv := NewStringTerraformFieldExpression()
	rv.SetExpression(v)
	return rv
}

func NewBoolTerraformFieldValueExpression(how bool) TerraformFieldExpression[bool] {
	rv := TerraformFieldExpression[bool]{
		IsNil: false,
		Value: how,
	}
	return rv
}
