Creates a version of a key in the destination key vault from the
provided ciphertext and additional parameters supplied as
resource attributes.

The resource can import RSA, Elliptic curve, and symmetric keys.

The ciphertext should be obtained using the `tfgen` command-line tool
(see [source code](https://github.com/aliakseiyanchuk/terraform-provider-az-confidential).)

A typical command for RSA and EC keys  would be:
```shell
tfgen -pubkey [path to the public key] \
	-fixed-labels demo,test \
	-output-vault [target vault name] -output-vault-object [target certificate name] \
	key
```
Symmetric keys need additional `-symmetric` flag:
```shell
tfgen -pubkey [path to the public key] \
	-fixed-labels demo,test \
	-output-vault [target vault name] -output-vault-object [target certificate name] \
	-symmetric \
	key
```