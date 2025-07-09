package resources

import (
	"context"
	"encoding/json"
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

type ConfidentialResourceSpecializer[TMdl any, TConfData any, AZAPIObject any] interface {
	SetFactory(factory core.AZClientsFactory)
	NewTerraformModel() TMdl
	ConvertToTerraform(azObj AZAPIObject, tfModel *TMdl) diag.Diagnostics
	GetConfidentialMaterialFrom(mdl TMdl) ConfidentialMaterialModel
	GetSupportedConfidentialMaterialTypes() []string
	CheckPlacement(ctx context.Context, uuid string, labels []string, tfModel *TMdl) diag.Diagnostics
	GetJsonDataImporter() core.ObjectJsonImportSupport[TConfData]

	DoRead(ctx context.Context, planData *TMdl) (AZAPIObject, ResourceExistenceCheck, diag.Diagnostics)
	DoCreate(ctx context.Context, planData *TMdl, plainData TConfData) (AZAPIObject, diag.Diagnostics)
	DoUpdate(ctx context.Context, planData *TMdl) (AZAPIObject, diag.Diagnostics)
	DoDelete(ctx context.Context, planData *TMdl) diag.Diagnostics
}

type ConfidentialGenericResource[TMdl, TIdentity any, TConfData any, AZAPIObject any] struct {
	ConfidentialResourceBase
	Specializer ConfidentialResourceSpecializer[TMdl, TConfData, AZAPIObject]

	ResourceType   string
	ResourceSchema schema.Schema
}

func (d *ConfidentialGenericResource[TMdl, TIdentity, TConfData, AZAPIObject]) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = fmt.Sprintf("%s_%s", req.ProviderTypeName, d.ResourceType)
}

func (d *ConfidentialGenericResource[TMdl, TIdentity, TConfData, AZAPIObject]) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	d.ConfidentialResourceBase.Configure(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		return
	}

	d.Specializer.SetFactory(d.factory)
}

func (d *ConfidentialGenericResource[TMdl, TIdentity, TConfData, AZAPIObject]) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = d.ResourceSchema
}

func (d *ConfidentialGenericResource[TMdl, TIdentity, TConfData, AZAPIObject]) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	data := d.Specializer.NewTerraformModel()

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	azObj, resourceExistenceCheck, dg := d.Specializer.DoRead(ctx, &data)
	dg.Append(dg...)

	// If there were errors in the process, return
	if dg.HasError() {
		return
	}

	if resourceExistenceCheck == ResourceNotFound {
		resp.State.RemoveResource(ctx)
	} else if resourceExistenceCheck == ResourceExists {
		convertDiagnostics := d.Specializer.ConvertToTerraform(azObj, &data)
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
	data := d.Specializer.NewTerraformModel()

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	plainText := d.ExtractConfidentialModelPlainText(ctx, d.Specializer.GetConfidentialMaterialFrom(data), &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	rawMsg := core.ConfidentialDataMessageJson{}
	if jsonErr := json.Unmarshal(plainText, &rawMsg); jsonErr != nil {
		resp.Diagnostics.AddError(
			"Cannot process plain-text data",
			fmt.Sprintf("The plain-text data does not conform to the minimal expected data structure requirements: %s", jsonErr.Error()),
		)

		return
	}

	if !slices.Contains(d.Specializer.GetSupportedConfidentialMaterialTypes(), rawMsg.Header.Type) {
		resp.Diagnostics.AddError("Unexpected object type", fmt.Sprintf(
			"Expected %s, got %s",
			d.Specializer.GetSupportedConfidentialMaterialTypes(),
			rawMsg.Header.Type))
		return
	}

	placementDiags := d.Specializer.CheckPlacement(ctx, rawMsg.Header.Uuid, rawMsg.Header.Labels, &data)
	resp.Diagnostics.Append(placementDiags...)
	if resp.Diagnostics.HasError() {
		tflog.Error(ctx, "checking possibility to place this object raised an error")
		return
	}

	importer := d.Specializer.GetJsonDataImporter()
	confidentialMaterial, importErr := importer.Import(rawMsg.ConfidentialData, rawMsg.Header.ModelReference)
	if importErr != nil {
		resp.Diagnostics.AddError(
			"Cannot parse confidential data",
			fmt.Sprintf("Plain text could not be parsed for further processing due to this error: %s. Are you specifying correct ciphertext for this resource?", importErr.Error()),
		)
		return
	}

	azObj, dg := d.Specializer.DoCreate(ctx, &data, confidentialMaterial)
	resp.Diagnostics.Append(dg...)
	if dg.HasError() {
		return
	}

	convertDiagnostics := d.Specializer.ConvertToTerraform(azObj, &data)
	if len(convertDiagnostics) > 0 {
		resp.Diagnostics.Append(convertDiagnostics...)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
	if trackErr := d.factory.TrackObjectId(ctx, rawMsg.Header.Uuid); trackErr != nil {
		errMsg := fmt.Sprintf("could not track the object entered into the state: %s", trackErr.Error())
		tflog.Error(ctx, errMsg)
		resp.Diagnostics.AddError("Incomplete object tracking", errMsg)
	}
}

func (d *ConfidentialGenericResource[TMdl, TIdentity, TConfData, AZAPIObject]) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	data := d.Specializer.NewTerraformModel()
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	azObj, dg := d.Specializer.DoUpdate(ctx, &data)
	resp.Diagnostics.Append(dg...)
	if dg.HasError() {
		return
	}

	convertDiagnostics := d.Specializer.ConvertToTerraform(azObj, &data)
	if len(convertDiagnostics) > 0 {
		resp.Diagnostics.Append(convertDiagnostics...)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (d *ConfidentialGenericResource[TMdl, TIdentity, TConfData, AZAPIObject]) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	data := d.Specializer.NewTerraformModel()

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	dg := d.Specializer.DoDelete(ctx, &data)
	resp.Diagnostics.Append(dg...)
}

// Ensure compilation of the resources
var _ resource.Resource = &ConfidentialGenericResource[string, int, int, string]{}
