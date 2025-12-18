# Present Proof Plugin

## Description

This plugin enable the v1 presentation exchange protocol for verifiable credentials.

## Configuration

***Important***: This plugin has a direct dependency with the issue_credential plugin. If you are using present proof you should also enable issue_credential. It will install issue_credential if not already installed.

This is done because each protocol will override the oob invitation handler and it isn't ensured which one will be the last to be registered. Also both protocols are often used together.

To enable the present proof plugin, add the following to your `config.yml` file:

```
pip install git+https://github.com/openwallet-foundation/acapy-plugins@main#subdirectory=present_proof
pip install git+https://github.com/openwallet-foundation/acapy-plugins@main#subdirectory=issue_credential
```

```yaml
plugin:
  - present_proof.v1_0
  - issue_credential.v1_0
```
