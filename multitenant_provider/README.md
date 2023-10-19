### Description:

Provides support for multiple tenants by creating jwt based athentication tokens for each tenant wallet.

This plugin requires that acapy is running in multitenant mode. this plugin will load a new Profile Manager in place of the one loaded by Aca-py, and subsequent calls for a Multitenant Profile Manager will use the class configured in this plugin.

The default manager classes provided in this plugin allow multiple tokens per wallet.

The `class_name` is the fully qualified class name/path.
The `always_check_provided_wallet_key` indicates whether we should check provided wallet_key values (required or not) when creating a token.

### Configuation:

```
# Multi-tenancy
multitenant: true
jwt-secret: insecure-jwt-secret
multitenant-admin: true

plugin:
  # load this plugin, note multitenant must be true
  - multitenant_provider.v1_0

plugin-config-value:
  - multitenant_provider.manager.class_name="multitenant_provider.v1_0.manager.BasicMultitokenMultitenantManager"
  - multitenant_provider.manager.always_check_provided_wallet_key=true
```

The expiry time for the token is also configurable. By default, a token is valid for 52 weeks.  
Possible units are weeks, days, hours, minutes. The following example will build tokens that expire in 30 minutes.

```
plugin-config-value:
  - multitenant_provider.token_expiry.units=days
  - multitenant_provider.token_expiry.amount=1
```

And we can configure whether to throw an error when a managed wallet passes in a wallet key when getting a token (default is true).

```
plugin-config-value:
 - multitenant_provider.errors.on_unneeded_wallet_key=true
```

#### askar vs basic/indy

There are 2 multitoken manager classes provided in this plugin: one for indy wallet types, one for askar wallet types.  
If there is no specific configuration provided for `multitenant_provider.manager.class_name`, we will look at the `wallet_type` (not the `multitenancy-config.wallet_type`). if `wallet_type=askar` then we will load `multitenant_provider.v1_0.manager.AskarMultitokenMultitenantManager` else we will load `multitenant_provider.v1_0.manager.BasicMultitokenMultitenantManager`.

### build and run

```
cd docker
docker build -f ./Dockerfile --tag multitenant_provider ..
docker run -it -p 3000:3000 -p 3001:3001 --rm multitenant_provider
```
