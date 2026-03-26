# MSO MDOC Credential Format

Implementation of ISO/IEC 18013-5:2021 compliant mobile document (mDoc) credential format for ACA-Py.

## Overview

This module provides support for issuing and verifying mobile documents (mDocs) as defined in ISO 18013-5, including mobile driver's licenses (mDL) and other identity credentials. The implementation uses the `isomdl-uniffi` library for core mDoc operations and integrates with ACA-Py's credential issuance framework.

## Features

- **ISO 18013-5 Compliance**: Full compliance with the international standard for mobile documents
- **CBOR Encoding**: Efficient binary encoding using CBOR (RFC 8949)
- **COSE Signing**: Cryptographic protection using COSE (RFC 8152/9052)
- **Selective Disclosure**: Privacy-preserving attribute disclosure
- **OpenID4VCI Integration**: Seamless integration with OpenID for Verifiable Credential Issuance

## Protocol Support

- ISO/IEC 18013-5:2021 - Mobile driving licence (mDL) application
- RFC 8152 - CBOR Object Signing and Encryption (COSE)
- RFC 9052 - CBOR Object Signing and Encryption (COSE): Structures and Process
- RFC 8949 - Concise Binary Object Representation (CBOR)
- OpenID4VCI 1.0 - Verifiable Credential Issuance Protocol

## Installation

The mso_mdoc module is included as part of the oid4vc plugin. Dependencies are managed through UV:

```toml
dependencies = [
    "cbor2>=5.4.3",
    "cwt>=1.6.0",
    "pycose>=1.0.0",
    "isomdl-uniffi @ git+https://github.com/Indicio-tech/isomdl-uniffi.git@feat/x509#subdirectory=python",
]
```

## Usage

### Credential Issuance

The module automatically registers the `MsoMdocCredProcessor` with the credential processor registry:

```python
from mso_mdoc.cred_processor import MsoMdocCredProcessor

# The processor handles mso_mdoc format credentials
processor = MsoMdocCredProcessor()
```

### Supported Document Types

Common document type identifiers:
- `org.iso.18013.5.1.mDL` - Mobile driver's license
- Custom organizational document types following the reverse domain notation

### Configuration

Credentials are configured through the OpenID4VCI credential configuration:

```json
{
  "format": "mso_mdoc",
  "doctype": "org.iso.18013.5.1.mDL",
  "cryptographic_binding_methods_supported": ["jwk"],
  "credential_signing_alg_values_supported": ["ES256"]
}
```

## Architecture

### Core Components

- **`cred_processor.py`**: Main credential processor implementing the `Issuer` interface
- **`storage.py`**: Persistent storage for keys and certificates
- **`key_generation.py`**: Cryptographic key generation utilities
- **`mdoc/issuer.py`**: mDoc issuance operations
- **`mdoc/verifier.py`**: mDoc verification operations

### Key Management

The module supports:
- Automatic EC P-256 key generation
- Persistent key storage with metadata
- Certificate generation and management
- Verification method resolution

## API Endpoints

The module provides REST API endpoints for mDoc operations:

### Sign mDoc
```
POST /oid4vc/mdoc/sign
```

Request body:
```json
{
    "payload": {
        "doctype": "org.iso.18013.5.1.mDL",
        "claims": {
            "org.iso.18013.5.1": {
                "family_name": "Doe",
                "given_name": "John",
                "birth_date": "1990-01-01",
                "age_over_18": true
            }
        }
    },
    "headers": {
        "alg": "ES256"
    },
    "verificationMethod": "did:key:z6Mkn6z3Eg2mrgQmripNPGDybZYYojwZw1VPjRkCzbNV7JfN#0"
}
```

### Verify mDoc
```
POST /oid4vc/mdoc/verify
```

Request body:
```json
{
    "mDoc": "<base64-encoded-mdoc>",
    "nonce": "optional-nonce"
}
```

## Testing

Comprehensive test coverage including:
- Unit tests for all components
- Integration tests with real mDoc operations
- Real functional tests with actual cryptographic operations
- Compliance tests against ISO 18013-5 requirements

Run tests:
```bash
cd oid4vc
uv run pytest mso_mdoc/tests/ -v
```

Test categories:
- **Unit Tests**: Individual component testing
- **Integration Tests**: Cross-component functionality
- **Real Tests**: Actual mDoc operations with isomdl-uniffi
- **Storage Tests**: Persistent storage operations
- **Security Tests**: Cryptographic validation

## Security Considerations

- All cryptographic operations use industry-standard libraries
- Keys are generated using secure random sources (P-256 ECDSA)
- Private keys are stored securely in ACA-Py's encrypted wallet
- No hardcoded credentials or keys
- Full compliance with ISO 18013-5 security requirements
- COSE signing for tamper detection

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure `isomdl-uniffi` is properly installed
2. **Key Generation Failures**: Check that the wallet is properly initialized
3. **CBOR Encoding Errors**: Verify data types match ISO 18013-5 requirements
4. **Signature Verification Failures**: Ensure proper key material and algorithm support

### Debug Mode

Enable debug logging for detailed operation information:

```python
import logging

logging.getLogger("mso_mdoc").setLevel(logging.DEBUG)
```

## Contributing

When contributing to this module:

1. **Ensure ISO 18013-5 compliance** - All changes must maintain standard compliance
2. **Add comprehensive tests** - Both unit and integration tests for new features
3. **Update documentation** - Keep API documentation current
4. **Run security scans** - Use `bandit` to check for security issues
5. **Format code** - Use `black` and `isort` for consistent formatting
6. **Type hints** - Maintain complete type annotations

### Development Setup

```bash
# Install development dependencies
uv sync --dev

# Run tests
cd oid4vc
uv run pytest mso_mdoc/tests/

# Run security scan
uv run bandit -r mso_mdoc/ -x "*/tests/*"

# Format code
uv run black mso_mdoc/
uv run isort mso_mdoc/
```

## License

This module is part of the Aries ACA-Py plugins project and follows the same licensing terms.

## References

- [ISO/IEC 18013-5:2021](https://www.iso.org/standard/69084.html) - Mobile driving licence (mDL) application
- [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- [RFC 8152 - CBOR Object Signing and Encryption (COSE)](https://tools.ietf.org/html/rfc8152)
- [RFC 8949 - Concise Binary Object Representation (CBOR)](https://tools.ietf.org/html/rfc8949)
