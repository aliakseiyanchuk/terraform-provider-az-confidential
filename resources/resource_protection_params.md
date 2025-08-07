# Secondary protection parameters
The primary protection of the confidential content is achieved with RSA encryption.

The secondary protection parameters can be additionally embedded into the
ciphertext that limits the usage the `az-confidential` provider
will observe.
Where any of these  parameters of is not met, the `az-confidential` provider
will generate an error. Removing an error will require re-encryption of the ciphertext
by the original confidential asset owner or a removal of the associated resource from the state.

> Note that secondary protection measures are implemented only by the `az-confidential` provider
> as a means to prevent inadvertent mix-ups and to enforce ciphertext re-encryption (which is
> equivalent of re-authenticating a user session after a prolonged use). Secondary protection is a
> _complimentary_ measure to RSA encryption and not a replacement thereof as any process or persona
> with the permission to decrypt the ciphertext using the matching private key wil be able
> to read the confidential material.

If this parameter is set to `null`, this will remove all secondary protection from the
ciphertext completely.

Available secondary protection parameter options are:
- `create_limit`: a time frame within which the object must be created. The value should
  be a valid Golang duration expression specifying hours, mines, and seconds. For example,
  `72h` expression limits the creation of the resource within 3 calendar days. To disable this
  limit, set this parameter to an empty string (`""`).
  > As a secure practice, the creation limit should be short-lived just enough to get the
  > actual resource created in Azure for production resource. Where the practitioner seeks
  > to recreate objects e.g., in ephemeral test environments, limiting expiry with `expirys_after`
  > and `num_uses` offers a suitable alternative.
- `expires_after`: number of days the before the ciphertext will be considered "expired." Set to
  `0` to mark the ciphertext perpetually valid.
- `num_uses`: number of times this ciphertext may be read before considered "depleted." Set to
  `0` to mark the ciphertext as non-depletable.
- `provider_constraints`: a set of strings indicating the tags an instance of `az-confidential`
  provider must be configured with. The primary use of this configuration is to add environmental
  constraints into the ciphertext to prevent production confidential material being accidentally used, 
  e.g. in the test environments.