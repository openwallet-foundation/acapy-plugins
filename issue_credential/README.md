# Issue Credential Plugin

## Description

This plugin enable the v1 Issue Credential protocol for verifiable credentials.

## Configuration

***Important***: This plugin has a direct dependency with the present_proof plugin. If you are using present proof you should also enable present_proof. It will install present_proof if not already installed.

This is done because each protocol will override the oob invitation handler and it isn't ensured which one will be the last to be registered. Also both protocols are often used together.

To enable the present proof plugin, add the following to your `config.yml` file:

```yaml
plugins:
    - issue_credential.v1_0
    - present_proof.v1_0
```
