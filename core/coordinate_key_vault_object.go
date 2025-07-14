package core

import "fmt"

// AzKeyVaultObjectCoordinate computed runtime coordinate
type AzKeyVaultObjectCoordinate struct {
	VaultName  string
	idHostName string // Name of the host as fully specified
	Name       string
	Type       string
}

func (c *AzKeyVaultObjectCoordinate) AsString() string {
	return fmt.Sprintf("v:=%s/t=%s/n=%s", c.VaultName, c.Type, c.Name)
}

func (c *AzKeyVaultObjectCoordinate) Clone() AzKeyVaultObjectCoordinate {
	return AzKeyVaultObjectCoordinate{
		VaultName:  c.VaultName,
		idHostName: c.idHostName,
		Name:       c.Name,
		Type:       c.Type,
	}
}

func (c *AzKeyVaultObjectCoordinate) SameAs(other AzKeyVaultObjectCoordinate) bool {
	return c.VaultName == other.VaultName &&
		c.Name == other.Name &&
		c.Type == other.Type
}

func (c *AzKeyVaultObjectCoordinate) DefinesVaultName() bool {
	return len(c.VaultName) > 0
}

func (c *AzKeyVaultObjectCoordinate) GetLabel() string {
	return fmt.Sprintf("az-c-label://%s/%s@%s;", c.VaultName, c.Name, c.Type)
}
