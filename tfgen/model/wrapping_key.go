package model

type WrappingKey struct {
	VaultName  TerraformFieldExpression[string]
	KeyName    TerraformFieldExpression[string]
	KeyVersion TerraformFieldExpression[string]
	Algorithm  TerraformFieldExpression[string]
}

func (w *WrappingKey) IsEmpty() bool {
	defined := w.VaultName.IsDefined() ||
		w.KeyName.IsDefined()

	return !defined
}

func NewWrappingKey() WrappingKey {
	return WrappingKey{
		VaultName:  NewStringTerraformFieldExpression(),
		KeyName:    NewStringTerraformFieldExpression(),
		KeyVersion: NewStringTerraformFieldExpression(),
		Algorithm:  NewStringTerraformFieldExpression(),
	}
}

func NewWrappingKeyForExpressions(vaultNameExpr, keyNameExpr, keyVersionExpr string) WrappingKey {
	rv := NewWrappingKey()

	if len(vaultNameExpr) > 0 {
		rv.VaultName.SetExpression(vaultNameExpr)
	}

	if len(keyNameExpr) > 0 {
		rv.KeyName.SetExpression(vaultNameExpr)
	}

	if len(keyVersionExpr) > 0 {
		rv.KeyVersion.SetExpression(keyVersionExpr)
	}

	return rv
}
