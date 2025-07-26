Datasource unwrapping (potentially very long) content into state

This resource is an illustration of how to overcome the limitation of RSA encryption
which cannot, on its own, encrypt a very large file.

The ciphertext should be obtained using the `tfgen` command-line tool
(see [source code](https://github.com/aliakseiyanchuk/terraform-provider-az-confidential-tfgen).)
A typical command usage would be:
```shell
tfgen -pubkey [path to the public key] \
	-fixed-labels demo,test \
	password
```