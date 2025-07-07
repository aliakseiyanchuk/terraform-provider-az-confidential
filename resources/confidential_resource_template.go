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

type ConfidentialResourceSpecializer[TMdl any, TConfData core.VersionedConfidentialData, AZAPIObject any] interface {
	SetFactory(factory core.AZClientsFactory)
	NewTerraformModel() TMdl
	ConvertToTerraform(azObj AZAPIObject, tfModel *TMdl) diag.Diagnostics
	GetConfidentialMaterialFrom(mdl TMdl) ConfidentialMaterialModel
	GetSupportedConfidentialMaterialTypes() []string
	CheckPlacement(ctx context.Context, tfModel *TMdl, cf TConfData) diag.Diagnostics
	GetPlaintextImporter() core.ObjectExportSupport[TConfData, []byte]

	DoRead(ctx context.Context, planData *TMdl) (AZAPIObject, ResourceExistenceCheck, diag.Diagnostics)
	DoCreate(ctx context.Context, planData *TMdl, plainData TConfData) (AZAPIObject, diag.Diagnostics)
	DoUpdate(ctx context.Context, planData *TMdl) (AZAPIObject, diag.Diagnostics)
	DoDelete(ctx context.Context, planData *TMdl) diag.Diagnostics
}

type ConfidentialGenericResource[TMdl, TIdentity any, TConfData core.VersionedConfidentialData, AZAPIObject any] struct {
	ConfidentialResourceBase
	specializer ConfidentialResourceSpecializer[TMdl, TConfData, AZAPIObject]

	resourceType   string
	resourceSchema schema.Schema
}

func (d *ConfidentialGenericResource[TMdl, TIdentity, TConfData, AZAPIObject]) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = fmt.Sprintf("%s_%s", req.ProviderTypeName, d.resourceType)
}

func (d *ConfidentialGenericResource[TMdl, TIdentity, TConfData, AZAPIObject]) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	d.ConfidentialResourceBase.Configure(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		return
	}

	d.specializer.SetFactory(d.factory)
}

func (d *ConfidentialGenericResource[TMdl, TIdentity, TConfData, AZAPIObject]) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = d.resourceSchema
}

func (d *ConfidentialGenericResource[TMdl, TIdentity, TConfData, AZAPIObject]) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
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

		resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
	} else if resourceExistenceCheck == ResourceCheckError {
		tflog.Error(ctx, "Failed to check the existence of resource during read; consult diagnostic messages")
	} else {
		tflog.Debug(ctx, "resource does not exist yet")
	}
}

func (d *ConfidentialGenericResource[TMdl, TIdentity, TConfData, AZAPIObject]) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	data := d.specializer.NewTerraformModel()

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	plainText := d.ExtractConfidentialModelPlainText(ctx, d.specializer.GetConfidentialMaterialFrom(data), &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	importer := d.specializer.GetPlaintextImporter()
	confidentialMaterial, importErr := importer.Import(plainText)
	if importErr != nil {
		resp.Diagnostics.AddError(
			"Cannot parse plain text",
			fmt.Sprintf("Plain text could not be parsed for further processing due to this error: %s. Are you specifying correct ciphertext for this resource?", importErr.Error()),
		)
		return
	}

	if !slices.Contains(d.specializer.GetSupportedConfidentialMaterialTypes(), confidentialMaterial.GetType()) {
		resp.Diagnostics.AddError("Unexpected object type", fmt.Sprintf(
			"Expected %s, got %s",
			d.specializer.GetSupportedConfidentialMaterialTypes(),
			confidentialMaterial.GetType()))
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

	d.FlushState(ctx, confidentialMaterial.GetUUID(), &data, resp)
}

func (d *ConfidentialGenericResource[TMdl, TIdentity, TConfData, AZAPIObject]) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
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

func (d *ConfidentialGenericResource[TMdl, TIdentity, TConfData, AZAPIObject]) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
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
var _ resource.Resource = &ConfidentialGenericResource[string, int, core.VersionedConfidentialData, string]{}
