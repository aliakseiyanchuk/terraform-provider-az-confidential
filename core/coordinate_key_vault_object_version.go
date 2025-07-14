package core

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"net/url"
	"strings"
)

type AzKeyVaultObjectVersionedCoordinate struct {
	AzKeyVaultObjectCoordinate
	Version string
}

func (c *AzKeyVaultObjectVersionedCoordinate) Clone() AzKeyVaultObjectVersionedCoordinate {
	return AzKeyVaultObjectVersionedCoordinate{
		AzKeyVaultObjectCoordinate: c.AzKeyVaultObjectCoordinate.Clone(),
		Version:                    c.Version,
	}
}

func (c *AzKeyVaultObjectVersionedCoordinate) SameAs(other AzKeyVaultObjectVersionedCoordinate) bool {
	return c.Version == other.Version &&
		c.AzKeyVaultObjectCoordinate.SameAs(other.AzKeyVaultObjectCoordinate)
}

func (c *AzKeyVaultObjectVersionedCoordinate) FromId(id string) error {
	if parsedURL, err := url.Parse(id); err != nil {
		return err
	} else {
		c.idHostName = parsedURL.Host
		c.VaultName = strings.Split(parsedURL.Host, ".")[0]
		parsedPath := strings.Split(strings.Trim(parsedURL.Path, "/"), "/")

		if len(parsedPath) != 3 {
			return fmt.Errorf("invalid reosurce path: %s (id=%s)", parsedURL.Path, id)
		}

		c.Type = parsedPath[0]
		c.Name = parsedPath[1]
		c.Version = parsedPath[2]

		return nil
	}
}

func (c *AzKeyVaultObjectVersionedCoordinate) VersionlessId() string {
	return fmt.Sprintf("https://%s/%s/%s", c.idHostName, c.Type, c.Name)
}

type AzKeyVaultObjectVersionedCoordinateModel struct {
	AzResourceCoordinateModel
	AzKeyVaultObjectCoordinateModel

	Version types.String `tfsdk:"version"`
}

func (mdl *AzKeyVaultObjectVersionedCoordinateModel) IsEmpty() bool {
	return mdl.Version.IsNull() && mdl.Name.IsNull() && mdl.VaultName.IsNull() && mdl.ResourceId.IsNull()
}
