## Destination parameter
When specified, "locks" the destination named value in the specific API management
instance into which this named value can be unpacked. 

The object has the following fields:
  - `az_subscription_id` Azure subscription Id containing the API management service
    > Note: this parameter contains `az_` prefix to differentiate between Azure 
    > and API management subscriptions.
  - `resource_group` resource group containing the API management service
  - `api_management_name` API management service name in the resource group
  - `name` a name of the named value object to be created this API management service