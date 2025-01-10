"""Shared objects."""

from did_sdk_py import HederaClientProvider, OperatorConfig

instances_map = {}

def get_client_provider(network, operator_id, operator_key_der) -> HederaClientProvider:
    """Return client provider instance."""

    key = f"{network};{operator_id};{operator_key_der}"

    if key in instances_map:
        return instances_map[key]

    client_provider = HederaClientProvider(
        network_name=network,
        operator_config=OperatorConfig(
            account_id=operator_id,
            private_key_der=operator_key_der
            )
        )

    instances_map[key] = client_provider

    return client_provider

