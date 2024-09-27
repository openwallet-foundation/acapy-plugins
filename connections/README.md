# Connection Protocol

This Plugin implements [Aries RFC 0160: Connection Protocol][rfc].

[rfc]: https://hyperledger.github.io/aries-rfcs/latest/features/0160-connection-protocol/

## Description

This is a migration of the original connection protocol implementation in ACA-Py through version 1.0.0. The Connection Protocol has been deprecated in ACA-Py core since version [0.12.0][v0.12.0]. The protocol is scheduled for removal from ACA-Py starting from version 1.1.0 or later.

The Connection Protocol is included in LTS releases 0.11.X and 0.12.X. Users who currently depend on the Connection Protocol may continue to use these LTS releases until they reach end of life. For those who need features added since the LTS releases, they may use this Plugin to add support for the Connection Protocol back into releases where it was removed from Core.

Please be advised: it is NOT recommended to continue to depend on the Connection Protocol. All users should migrate to [0023 DID Exchange][didex] and [0434 Out of Band][oob] as soon as possible. Support for this protocol and plugin will be limited to bug fixes only and will eventually be abandoned altogether. Additionally, some bug reports may be met with a `WONTFIX` if the burden to support the fix is untenable.

[v0.12.0]: https://github.com/hyperledger/aries-cloudagent-python/blob/main/CHANGELOG.md#0120-breaking-changes
[didex]: https://hyperledger.github.io/aries-rfcs/latest/features/0023-did-exchange/
[oob]: https://hyperledger.github.io/aries-rfcs/latest/features/0434-outofband/

## Features Cut During Migration

Some features have been cut from this plugin in the process of migrating it from ACA-Py Core:

- Generating a connection invitation on startup
- Automatic mediator setup on startup using a connection invitation
- Automatic endorser setup on startup using a connection invitation
- Using `connection/1.0` as a handshake protocol for [Out-of-Band][oob] invitations

If you depend on one of these features, it is strongly recommended that you upgrade to [0023 DID Exchange][didex] and [0434 Out of Band][oob]. If this is not possible, the maintainers are open to guiding a community contribution to restore these features. However, at the maintainers discretion, the request may be denied if it breaks compatibility with upstream ACA-Py Core features.

## Configuration

To use this plugin, load it on startup of your ACA-Py instance with:

```
--plugin connectiosn
```

Or, using yaml configuration:
```yaml
plugin:
  - connections
```

No additional configuration is required.
