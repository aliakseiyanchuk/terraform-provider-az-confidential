package resources

import (
	"context"
	"fmt"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"slices"
)

type ResourceExistenceCheck int

const (
	ResourceExists ResourceExistenceCheck = iota
	ResourceNotFound
	ResourceNotYetCreated
	ResourceCheckError
)

// APIObjectToStateImporter an API object into th state
type APIObjectToStateImporter[TMdl, AZAPIObject any] func(azObj AZAPIObject, tfModel *TMdl)
type IdAssigner[TMdl, AZAPIObject any] func(azObj AZAPIObject, tfModel *TMdl)

type ConfidentialMaterialLocator[TMdl any] func(mdl TMdl) ConfidentialMaterialModel
type PlacementChecker func(ctx context.Context, cf core.VersionedConfidentialData, diagnostics *diag.Diagnostics)

type ConfidentialResourceSpecializer[TMdl, AZAPIObject any] interface {
	SetFactory(factory core.AZClientsFactory)
	NewTerraformModel() TMdl
	AssignIdTo(azObj AZAPIObject, tfModel *TMdl)
	ConvertToTerraform(azObj AZAPIObject, tfModel *TMdl) diag.Diagnostics
	GetConfidentialMaterialFrom(mdl TMdl) ConfidentialMaterialModel
	GetSupportedConfidentialMaterialTypes() []string
	CheckPlacement(ctx context.Context, tfModel *TMdl, cf core.VersionedConfidentialData) diag.Diagnostics

	DoRead(_ context.Context, planData *TMdl) (AZAPIObject, ResourceExistenceCheck, diag.Diagnostics)
	DoCreate(_ context.Context, planData *TMdl, unwrappedData core.VersionedConfidentialData) (AZAPIObject, diag.Diagnostics)
	DoUpdate(ctx context.Context, planData *TMdl) (AZAPIObject, diag.Diagnostics)
	DoDelete(ctx context.Context, planData *TMdl) diag.Diagnostics
}

type ConfidentialGenericResource[TMdl, TIdentity, AZAPIObject any] struct {
	ConfidentialResourceBase
	specializer ConfidentialResourceSpecializer[TMdl, AZAPIObject]

	resourceType   string
	resourceSchema schema.Schema
}

func (d *ConfidentialGenericResource[TMdl, TIdentity, AZAPIObject]) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = fmt.Sprintf("%s_%s", req.ProviderTypeName, d.resourceType)
}

func (d *ConfidentialGenericResource[TMdl, TIdentity, AZAPIObject]) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	d.ConfidentialResourceBase.Configure(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		return
	}

	d.specializer.SetFactory(d.factory)
}

func (d *ConfidentialGenericResource[TMdl, TIdentity, AZAPIObject]) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = d.resourceSchema
}

func (d *ConfidentialGenericResource[TMdl, TIdentity, AZAPIObject]) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	data := d.specializer.NewTerraformModel()

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	azObj, resourceExistenceCheck, dg := d.specializer.DoRead(ctx, &data)
	dg.Append(dg...)

	// If there were errors in the process, return
	if dg.HasError() {
		return
	}

	if resourceExistenceCheck == ResourceNotFound {
		resp.State.RemoveResource(ctx)
	} else if resourceExistenceCheck == ResourceExists {
		convertDiagnostics := d.specializer.ConvertToTerraform(azObj, &data)
		if len(convertDiagnostics) > 0 {
			resp.Diagnostics.Append(convertDiagnostics...)
		}

		d.specializer.AssignIdTo(azObj, &data)
		resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
	} else if resourceExistenceCheck == ResourceCheckError {
		tflog.Error(ctx, "Failed to check the existence of resource during read; consult diagnostic messages")
	} else {
		tflog.Debug(ctx, "resource does not exist yet")
	}
}

func (d *ConfidentialGenericResource[TMdl, TIdentity, AZAPIObject]) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	data := d.specializer.NewTerraformModel()

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	confidentialMaterial := d.UnwrapEncryptedConfidentialData(ctx, d.specializer.GetConfidentialMaterialFrom(data), &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	if !slices.Contains(d.specializer.GetSupportedConfidentialMaterialTypes(), confidentialMaterial.Type) {
		resp.Diagnostics.AddError("Unexpected object type", fmt.Sprintf(
			"Expected %s, got %s",
			d.specializer.GetSupportedConfidentialMaterialTypes(),
			confidentialMaterial.Type))
		return
	}

	placementDiags := d.specializer.CheckPlacement(ctx, &data, confidentialMaterial)
	resp.Diagnostics.Append(placementDiags...)
	if resp.Diagnostics.HasError() {
		tflog.Error(ctx, "checking possibility to place this object raised an error")
		return
	}

	azObj, dg := d.specializer.DoCreate(ctx, &data, confidentialMaterial)
	resp.Diagnostics.Append(dg...)
	if dg.HasError() {
		return
	}

	convertDiagnostics := d.specializer.ConvertToTerraform(azObj, &data)
	if len(convertDiagnostics) > 0 {
		resp.Diagnostics.Append(convertDiagnostics...)
	}

	d.specializer.AssignIdTo(azObj, &data)

	d.FlushState(ctx, confidentialMaterial.Uuid, &data, resp)
}

func (d *ConfidentialGenericResource[TMdl, TIdentity, AZAPIObject]) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	data := d.specializer.NewTerraformModel()
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	azObj, dg := d.specializer.DoUpdate(ctx, &data)
	resp.Diagnostics.Append(dg...)
	if dg.HasError() {
		return
	}

	convertDiagnostics := d.specializer.ConvertToTerraform(azObj, &data)
	if len(convertDiagnostics) > 0 {
		resp.Diagnostics.Append(convertDiagnostics...)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (d *ConfidentialGenericResource[TMdl, TIdentity, AZAPIObject]) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	data := d.specializer.NewTerraformModel()

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	dg := d.specializer.DoDelete(ctx, &data)
	resp.Diagnostics.Append(dg...)
}

// Ensure compilation of the resources
var _ resource.Resource = &ConfidentialGenericResource[string, int, string]{}
