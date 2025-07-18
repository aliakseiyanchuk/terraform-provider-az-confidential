package keyvault

import (
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/model"
)

type ObjectCoordinateModel struct {
	VaultName  model.TerraformFieldExpression[string]
	ObjectName model.TerraformFieldExpression[string]
}

func NewObjectCoordinateModel(vaultName, objectName string) ObjectCoordinateModel {
	return NewObjectCoordinateModelUsingFn(
		vaultName,
		objectName,
		func(m *model.TerraformFieldExpression[string], str string) { m.SetValue(str) },
	)
}

func NewObjectCoordinateModelUsingExpressions(vaultName, objectName string) ObjectCoordinateModel {
	return NewObjectCoordinateModelUsingFn(
		vaultName,
		objectName,
		func(m *model.TerraformFieldExpression[string], s string) { m.SetExpression(s) },
	)
}

func NewObjectCoordinateModelUsingFn(vaultName, objectName string, fn core.BiConsumer[*model.TerraformFieldExpression[string], string]) ObjectCoordinateModel {
	rv := ObjectCoordinateModel{
		VaultName:  model.NewStringTerraformFieldExpression(),
		ObjectName: model.NewStringTerraformFieldExpression(),
	}

	if len(vaultName) > 0 {
		fn(&rv.VaultName, vaultName)
	}

	if len(objectName) > 0 {
		fn(&rv.ObjectName, objectName)
	}

	return rv
}

type TerraformCodeModel struct {
	model.BaseTerraformCodeModel
	model.TagsModel

	DestinationCoordinate ObjectCoordinateModel
	NotBeforeExample      string
	NotAfterExample       string

	IsSpecified bool
}
