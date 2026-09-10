"""Global constants."""


class OAuth2Flow:
    """Internal flow identifiers."""

    PRE_AUTH_CODE = "pre_auth_code"
    REFRESH_TOKEN = "refresh_token"


class OAuth2GrantType:
    """Wire-level grant_type URNs."""

    PRE_AUTH_CODE = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    REFRESH_TOKEN = "refresh_token"


class ClientAuthMethod:
    """token_endpoint_auth_method values."""

    CLIENT_SECRET_BASIC = "client_secret_basic"
    PRIVATE_KEY_JWT = "private_key_jwt"


CLIENT_AUTH_METHODS: tuple[str, ...] = (
    ClientAuthMethod.CLIENT_SECRET_BASIC,
    ClientAuthMethod.PRIVATE_KEY_JWT,
)

SUPPORTED_SIGNING_ALGS: tuple[str, ...] = ("ES256", "EdDSA", "ES384")

# Mapping from signing algorithm to joserfc key family ("EC" or "OKP")
ALG_KEY_FAMILY: dict[str, str] = {
    "ES256": "EC",
    "ES384": "EC",
    "EdDSA": "OKP",
}

PBKDF2_ALLOWED_ALGOS: frozenset[str] = frozenset({"sha256", "sha384", "sha512"})
