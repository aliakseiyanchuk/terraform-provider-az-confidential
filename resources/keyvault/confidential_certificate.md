Creates a version of a certificate in the destination key vault from the
provided ciphertext and additional parameters supplied as
resource attributes.

The ciphertext should be obtained using the `tfgen` command-line tool
(see [source code](https://github.com/aliakseiyanchuk/terraform-provider-az-confidential-tfgen).)
A typical command usage would be:
```shell
tfgen -pubkey [path to the public key] \
	-fixed-labels demo,test \
	-output-vault [target vault name] -output-vault-object [target certificate name] \
	certificate
```