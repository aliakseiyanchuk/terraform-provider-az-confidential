Creates a version of a secret in the destination key vault from the
provided ciphertext and additional parameters supplied as
resource attributes.

The ciphertext should be obtained using the `tfgen` command-line tool
(see [source code](https://github.com/aliakseiyanchuk/terraform-provider-az-confidential).)
A typical command usage would be:
```shell
tfget -pubkey [path to the public key] \
	-fixed-labels demo,test \
	-output-vault [target vault name] -output-vault-object [target certificate name] \
	secret
```