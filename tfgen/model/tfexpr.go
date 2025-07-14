package model

import (
	"fmt"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
)

type TerraformFieldExpression[T any] struct {
	Value      *T
	Mapper     core.Mapper[T, string]
	Expression string
	Include    bool
}

func (expr *TerraformFieldExpression[T]) IsSpecified() bool {
	return expr.Value != nil || expr.Expression != ""
}

func (expr *TerraformFieldExpression[T]) SetValue(v *T) {
	expr.Value = v
	expr.Expression = ""
}

func (expr *TerraformFieldExpression[T]) SetExpression(e string) {
	expr.Value = nil
	expr.Expression = e
}

func (expr *TerraformFieldExpression[T]) IsIncluded() bool {
	return !expr.Include
}

func (expr *TerraformFieldExpression[T]) IsDefined() bool {
	return expr.Value != nil
}

func (expr *TerraformFieldExpression[T]) TerraformExpression() string {
	if len(expr.Expression) > 0 {
		return expr.Expression
	}

	if expr.Value == nil {
		return "null"
	}

	if expr.Mapper == nil {
		return fmt.Sprint(*expr.Value)
	} else {
		return expr.Mapper(*expr.Value)
	}
}

func NewStringTerraformFieldExpression() TerraformFieldExpression[string] {
	rv := TerraformFieldExpression[string]{
		Mapper: func(s string) string { return fmt.Sprintf("\"%s\"", s) },
	}
	return rv
}
