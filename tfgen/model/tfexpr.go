package model

import (
	"fmt"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
)

type TerraformFieldExpression[T any] struct {
	Value      T
	IsNil      bool
	Mapper     core.Mapper[T, string]
	Expression string
	Include    bool
}

func (expr *TerraformFieldExpression[T]) IsSpecified() bool {
	return !expr.IsNil || expr.Expression != ""
}

func (expr *TerraformFieldExpression[T]) SetValue(v T) {
	expr.Value = v
	expr.IsNil = false
	expr.Expression = ""
}

func (expr *TerraformFieldExpression[T]) SetExpression(e string) {
	expr.IsNil = false
	expr.Expression = e
}

func (expr *TerraformFieldExpression[T]) SetNil() {
	expr.IsNil = true
	expr.Expression = ""
}

func (expr *TerraformFieldExpression[T]) IsIncluded() bool {
	return !expr.Include
}

func (expr *TerraformFieldExpression[T]) IsDefined() bool {
	return !expr.IsNil
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
		IsNil:  true,
		Mapper: func(s string) string { return fmt.Sprintf("\"%s\"", s) },
	}
	return rv
}
