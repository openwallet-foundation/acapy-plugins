"""Client helpers."""

from hiero_sdk_python import Client, Network, AccountId, PrivateKey

instances_map = {}


def get_client(network, operator_id, operator_key) -> Client:
    """Return client provider instance."""

    key = f"{network};{operator_id};{operator_key}"

    if key in instances_map:
        return instances_map[key]

    client = Client(network=Network(network))
    client.set_operator(
        AccountId.from_string(operator_id), PrivateKey.from_string(operator_key)
    )

    instances_map[key] = client

    return client
