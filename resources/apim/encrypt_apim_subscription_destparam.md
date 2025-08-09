## Destination parameter
When specified, "locks" the destination subscription in the specific API management
instance into which this subscription can be unpacked. 

The object has the following fields:
  - `az_subscription_id` Azure subscription Id containing the API management service. Required to lock destination.
    > Note: this parameter contains `az_` prefix to differentiate between Azure 
    > and API management subscriptions.
  - `resource_group` resource group containing the API management service. Required to lock destination.
  - `api_management_name` API management service name in the resource group. Required to lock destination.
  - `apim_subscription_id` specific API subscription id to assign ot thi subscription
  - `api_id` an identifier of the API to link this subscription to. A non-empty value is mutually exclusive  
     with `product_id` set to an non-empty string.
  - `product_id` an identifier of the API production to link subscription to. A non-empty value is mutually exclusive  
    with `api_id` set to an non-empty string.
  - `user_id` an id of the owner to be associated with this subscription.  