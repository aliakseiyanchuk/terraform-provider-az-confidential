package resources

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type ResourceExistenceCheck int

const (
	ResourceCheckNotAttempted ResourceExistenceCheck = iota
	ResourceExists
	ResourceNotFound
	ResourceNotYetCreated
	ResourceCheckError
	ResourceConfidentialDataDrift
)

func (t ResourceExistenceCheck) String() string {
	switch t {
	case ResourceCheckNotAttempted:
		return "check never attempted"
	case ResourceExists:
		return "does not exist"
	case ResourceNotFound:
		return "not found (deleted outside of Terraform control)"
	case ResourceNotYetCreated:
		return "not yet created"
	case ResourceCheckError:
		return "checking erred"
	case ResourceConfidentialDataDrift:
		return "detected drift in the confidential material"
	default:
		return fmt.Sprintf("unkonwn check type %d", t)
	}
}

// APIObjectToStateImporter an API object into the state
type APIObjectToStateImporter[TMdl, AZAPIObject any] func(azObj AZAPIObject, tfModel *TMdl)
type IdAssigner[TMdl, AZAPIObject any] func(azObj AZAPIObject, tfModel *TMdl)

type ConfidentialMaterialLocator[TMdl any] func(mdl TMdl) ConfidentialMaterialModel

type CommonConfidentialResourceSpecialization[TMdl any, TConfData any, AZAPIObject any] interface {
	SetFactory(factory core.AZClientsFactory)
	NewTerraformModel() TMdl
	ConvertToTerraform(azObj AZAPIObject, tfModel *TMdl) diag.Diagnostics
	GetConfidentialMaterialFrom(mdl TMdl) ConfidentialMaterialModel
	Decrypt(ctx context.Context, em core.EncryptedMessage, decr core.RSADecrypter) (core.ConfidentialDataJsonHeader, TConfData, error)
	CheckPlacement(ctx context.Context, providerConstraints []core.ProviderConstraint, placementConstraints []core.PlacementConstraint, tfModel *TMdl) diag.Diagnostics

	DoCreate(ctx context.Context, planData *TMdl, plainData TConfData) (AZAPIObject, diag.Diagnostics)
	DoDelete(ctx context.Context, planData *TMdl) diag.Diagnostics
}

type ImmutableConfidentialResourceRU[TMdl any, TConfData any, AZAPIObject any] interface {
	DoRead(ctx context.Context, planData *TMdl) (AZAPIObject, ResourceExistenceCheck, diag.Diagnostics)
	DoUpdate(ctx context.Context, planData *TMdl) (AZAPIObject, diag.Diagnostics)
}

type MutableConfidentialResourceRU[TMdl any, TConfData any, AZAPIObject any] interface {
	DoRead(ctx context.Context, planData *TMdl, lainData TConfData) (AZAPIObject, ResourceExistenceCheck, diag.Diagnostics)
	DoUpdate(ctx context.Context, planData *TMdl, lainData TConfData) (AZAPIObject, diag.Diagnostics)
	// SetDriftToConfidentialData changes the confidential data on the plan to trigger the
	// update.
	SetDriftToConfidentialData(ctx context.Context, planData *TMdl)
}

type RequestAbstraction struct {
	Get      func(ctx context.Context, val interface{}) diag.Diagnostics
	HasError func() bool
}

type ResponseAbstraction struct {
	Set            func(ctx context.Context, val interface{}) diag.Diagnostics
	RemoveResource func(context.Context)
	Diagnostics    *diag.Diagnostics
}

type ConfidentialGenericResource[TMdl, TIdentity any, TConfData any, AZAPIObject any] struct {
	ConfidentialResourceBase
	Specializer CommonConfidentialResourceSpecialization[TMdl, TConfData, AZAPIObject]
	ImmutableRU ImmutableConfidentialResourceRU[TMdl, TConfData, AZAPIObject]
	MutableRU   MutableConfidentialResourceRU[TMdl, TConfData, AZAPIObject]

	ResourceName   string
	ResourceSchema schema.Schema
}

func (d *ConfidentialGenericResource[TMdl, TIdentity, TConfData, AZAPIObject]) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = fmt.Sprintf("%s_%s", req.ProviderTypeName, d.ResourceName)
}

func (d *ConfidentialGenericResource[TMdl, TIdentity, TConfData, AZAPIObject]) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	d.ConfidentialResourceBase.Configure(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		return
	}

	d.Specializer.SetFactory(d.Factory)
}

func (d *ConfidentialGenericResource[TMdl, TIdentity, TConfData, AZAPIObject]) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = d.ResourceSchema
}

func (d *ConfidentialGenericResource[TMdl, TIdentity, TConfData, AZAPIObject]) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	reqAbs := RequestAbstraction{
		Get: req.State.Get,
	}

	resAbs := ResponseAbstraction{
		Set:            resp.State.Set,
		RemoveResource: resp.State.RemoveResource,
		Diagnostics:    &resp.Diagnostics,
	}

	d.ReadT(ctx, reqAbs, resAbs)
}

func (d *ConfidentialGenericResource[TMdl, TIdentity, TConfData, AZAPIObject]) ReadT(ctx context.Context, req RequestAbstraction, resp ResponseAbstraction) {
	data := d.Specializer.NewTerraformModel()

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var azObj AZAPIObject
	var resourceExistenceCheck = ResourceCheckNotAttempted
	dg := diag.Diagnostics{}

	if d.ImmutableRU != nil {
		// Immutable read/update does not require decryption
		azObj, resourceExistenceCheck, dg = d.ImmutableRU.DoRead(ctx, &data)
	} else if d.MutableRU != nil {
		// Mutable read/update requires decryption of the ciphertext. Because the update presents the possibility
		// of the injection, the ciphertext is checked for correctness

		confMdl := d.Specializer.GetConfidentialMaterialFrom(data)
		if IsDriftMessage(confMdl.EncryptedSecret.ValueString()) {
			tflog.Warn(ctx, "This resource contains drift tag instead of confidential material; update will be performed via Terraform standard flow")
			return
		}

		em := core.EncryptedMessage{}
		if emImportErr := em.FromBase64PEM(confMdl.EncryptedSecret.ValueString()); emImportErr != nil {
			dg.AddError(
				"Confidential content does not conform to the expected format",
				fmt.Sprintf("Received this error while trying to parse the confidential message: %s. Confidential content shoud be produced either by tfgen tool or vai appropriate function", emImportErr.Error()),
			)
			return
		}

		rsaDecrypter := d.Factory.GetDecrypterFor(ctx, confMdl.WrappingKeyCoordinate)

		header, confData, err := d.Specializer.Decrypt(ctx, em, rsaDecrypter)
		if err != nil {
			dg.AddError(
				"Cannot decrypt ciphertext",
				fmt.Sprintf("Received this error while trying to decrypt the confidential message: %s. Confidential content shoud be produced either by tfgen tool or vai appropriate function and encrypted with the public key that this provider is using.", err.Error()),
			)
			return
		}

		d.CheckCiphertextExpiry(ctx, header, resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}

		placementDiags := d.Specializer.CheckPlacement(ctx, header.ProviderConstraints, header.PlacementConstraints, &data)
		resp.Diagnostics.Append(placementDiags...)
		if resp.Diagnostics.HasError() {
			tflog.Error(ctx, "checking possibility to place this object raised an error")
			return
		}

		// Object tracking lookup is not performed at this point. In mutable read/update, the practitioner
		// may have replaced the ciphertext with a new value or the state of the object may have drifted
		// from what the ciphertext declares. Using identity schema may offer a place to store this information;
		// however, it is not currently implemented due to Terraform version compatibility considerations.
		//
		// A recommended solution to use strict target labeling to counter the risk of copying an update.
		//
		// The update operation will track the object to make sure that new creations would not be possible.
		azObj, resourceExistenceCheck, dg = d.MutableRU.DoRead(ctx, &data, confData)
	} else {
		resp.Diagnostics.AddError("Incomplete resource configuration", "This resource does not define read/update methods")
		return
	}

	resp.Diagnostics.Append(dg...)
	if dg.HasError() {
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Resource existence check on read: %s", resourceExistenceCheck.String()))

	if resourceExistenceCheck == ResourceNotFound {
		resp.RemoveResource(ctx)
	} else if resourceExistenceCheck == ResourceExists || resourceExistenceCheck == ResourceConfidentialDataDrift {
		convertDiagnostics := d.Specializer.ConvertToTerraform(azObj, &data)
		if len(convertDiagnostics) > 0 {
			resp.Diagnostics.Append(convertDiagnostics...)
		}

		if resourceExistenceCheck == ResourceConfidentialDataDrift {
			tflog.Warn(ctx, "Read operation detected a drift in the confidential material")

			// If the state of the confidential data has drifted, a check is required as to why. It could be that
			// a new version of the ciphertext was supplied -- in that case, it is an in-place update
			// after the replacement of ciphertext. Otherwise, it's a change in Azure that needs to be
			// corrected back.

			d.MutableRU.SetDriftToConfidentialData(ctx, &data)
		}

		resp.Diagnostics.Append(resp.Set(ctx, &data)...)
	} else if resourceExistenceCheck == ResourceCheckError {
		tflog.Error(ctx, "Failed to check the existence of resource during read; consult diagnostic messages")
		if !resp.Diagnostics.HasError() {
			resp.Diagnostics.AddError("Missing read error reason", "An error was reported during reading this object without specifying the diagnostics. This is the error of az-confidential provider. Kindly please report this problem.")
		}
	} else {
		tflog.Debug(ctx, "resource does not exist yet")
	}
}

func (d *ConfidentialGenericResource[TMdl, TIdentity, TConfData, AZAPIObject]) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	reqAbs := RequestAbstraction{
		Get: req.Plan.Get,
	}

	resAbs := ResponseAbstraction{
		Set:            resp.State.Set,
		RemoveResource: resp.State.RemoveResource,
		Diagnostics:    &resp.Diagnostics,
	}

	d.CreateT(ctx, reqAbs, resAbs)
}

func (d *ConfidentialGenericResource[TMdl, TIdentity, TConfData, AZAPIObject]) CreateT(ctx context.Context, req RequestAbstraction, resp ResponseAbstraction) {
	data := d.Specializer.NewTerraformModel()

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	confMdl := d.Specializer.GetConfidentialMaterialFrom(data)
	em := core.EncryptedMessage{}
	if emImportErr := em.FromBase64PEM(confMdl.EncryptedSecret.ValueString()); emImportErr != nil {
		resp.Diagnostics.AddError(
			"Confidential content does not conform to the expected format",
			fmt.Sprintf("Received this error while trying to parse the confidential message: %s. Confidential content shoud be produced either by tfgen tool or vai appropriate function", emImportErr.Error()),
		)
		return
	}

	rsaDecrypter := d.Factory.GetDecrypterFor(ctx, confMdl.WrappingKeyCoordinate)

	header, confData, err := d.Specializer.Decrypt(ctx, em, rsaDecrypter)
	if err != nil {
		resp.Diagnostics.AddError(
			"Cannot decrypt ciphertext",
			fmt.Sprintf("Received this error while trying to decrypt the confidential message: %s. Confidential content shoud be produced either by tfgen tool or vai appropriate function and encrypted with the public key that this provider is using.", err.Error()),
		)
		return
	}

	d.CheckCiphertextExpiry(ctx, header, resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	d.CheckCiphertextCreateExpiry(ctx, header, resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	placementDiags := d.Specializer.CheckPlacement(ctx, header.ProviderConstraints, header.PlacementConstraints, &data)
	resp.Diagnostics.Append(placementDiags...)
	if resp.Diagnostics.HasError() {
		tflog.Error(ctx, "checking possibility to place this object raised an error")
		return
	}

	if header.NumUses > 0 && !d.Factory.IsObjectTrackingEnabled() {
		resp.Diagnostics.AddError(
			"Insecure provider configuration",
			"The ciphertext of this resource requires tracking the number of times this object is created, while this provider is not configured to do so. Please configure the provider to track objects",
		)
		return
	}

	if header.NumUses > 0 {
		// In case a ciphertext may be used several times, the usage is allowed to this limit
		if numTracked, ntErr := d.Factory.GetTackedObjectUses(ctx, header.Uuid); ntErr != nil {
			resp.Diagnostics.AddError(
				"Cannot assert the number of times this ciphertext was used",
				fmt.Sprintf("Attempt to check how many times the ciphertext was previously used to create a resource erred: %s", ntErr.Error()),
			)
			return
		} else if numTracked >= header.NumUses {
			resp.Diagnostics.AddError(
				"Ciphertext has been used all time it was allowed to do so",
				fmt.Sprintf("The use of this ciphertext to create Azure objects has been exhaused. Re-encrypt and replace the ciphertext to continue."),
			)
			return
		}
	}

	azObj, dg := d.Specializer.DoCreate(ctx, &data, confData)
	resp.Diagnostics.Append(dg...)
	if dg.HasError() {
		return
	}

	convertDiagnostics := d.Specializer.ConvertToTerraform(azObj, &data)
	if len(convertDiagnostics) > 0 {
		resp.Diagnostics.Append(convertDiagnostics...)
	}

	resp.Diagnostics.Append(resp.Set(ctx, &data)...)

	if header.NumUses > 0 {
		if trackErr := d.Factory.TrackObjectId(ctx, header.Uuid); trackErr != nil {
			errMsg := fmt.Sprintf("could not track the object entered into the state: %s", trackErr.Error())
			tflog.Error(ctx, errMsg)
			resp.Diagnostics.AddError("Incomplete object tracking", errMsg)
		}

		if numTracked, ntErr := d.Factory.GetTackedObjectUses(ctx, header.Uuid); ntErr != nil {
			resp.Diagnostics.AddError(
				"Cannot assert the number of times this ciphertext was used",
				fmt.Sprintf("Attempt to check how many times the ciphertext was previously used to create a resource erred: %s", ntErr.Error()),
			)
			return
		} else if numTracked == header.NumUses && header.NumUses > 1 {
			resp.Diagnostics.AddWarning(
				"No more resource create are possible",
				"The ciphertext allows limited number of times to create Azure objects. This was the last allowed create operation; no further creates using this ciphertext are possible. Recreate ciphertext of this resource",
			)
		}
	}
}

func CreateDriftMessage(tkn string) string {
	return fmt.Sprintf("---- DRIFT IN %s CONFIDENTIAL DATA ----", strings.ToUpper(tkn))
}

var driftMessageExpr = regexp.MustCompile("^---- DRIFT IN .* CONFIDENTIAL DATA ----$")

func IsDriftMessage(v string) bool {
	return driftMessageExpr.MatchString(v)
}

func (d *ConfidentialGenericResource[TMdl, TIdentity, TConfData, AZAPIObject]) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	data := d.Specializer.NewTerraformModel()
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	var azObj AZAPIObject
	var dg diag.Diagnostics

	if d.ImmutableRU != nil {
		// Immutable read/update does not require decryption
		azObj, dg = d.ImmutableRU.DoUpdate(ctx, &data)
	} else if d.MutableRU != nil {
		// Mutable read/update requires decryption. This process is simplified compared to create because
		// read operation should have done all the necessary checks.

		confMdl := d.Specializer.GetConfidentialMaterialFrom(data)

		em := core.EncryptedMessage{}
		if emImportErr := em.FromBase64PEM(confMdl.EncryptedSecret.ValueString()); emImportErr != nil {
			resp.Diagnostics.AddError(
				"Confidential content does not conform to the expected format",
				fmt.Sprintf("Received this error while trying to parse the confidential message: %s. Confidential content shoud be produced either by tfgen tool or vai appropriate function", emImportErr.Error()),
			)
			return
		}

		rsaDecrypter := d.Factory.GetDecrypterFor(ctx, confMdl.WrappingKeyCoordinate)

		header, confData, err := d.Specializer.Decrypt(ctx, em, rsaDecrypter)
		if err != nil {
			resp.Diagnostics.AddError(
				"Cannot decrypt ciphertext",
				fmt.Sprintf("Received this error while trying to decrypt the confidential message: %s. Confidential content shoud be produced either by tfgen tool or vai appropriate function and encrypted with the public key that this provider is using.", err.Error()),
			)
			return
		}

		azObj, dg = d.MutableRU.DoUpdate(ctx, &data, confData)

		// Track the object use
		if d.Factory.IsObjectTrackingEnabled() {
			objTracked, objTrackErr := d.Factory.IsObjectIdTracked(ctx, header.Uuid)
			if objTrackErr != nil {
				resp.Diagnostics.AddError(
					"Could not verify object tracking status after update",
					objTrackErr.Error(),
				)
			}
			if !objTracked {
				if trackErr := d.Factory.TrackObjectId(ctx, header.Uuid); trackErr != nil {
					resp.Diagnostics.AddError(
						"Could not track the ciphertext use at update",
						trackErr.Error(),
					)
				}
			}
		}

	} else {
		resp.Diagnostics.AddError("Incomplete resource configuration", "This resource does not define read/update methods")
		return
	}

	resp.Diagnostics.Append(dg...)
	if resp.Diagnostics.HasError() {
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
