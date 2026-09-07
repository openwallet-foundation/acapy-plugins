"""Class for parsing indy_ledger plugin arguments."""

import logging

import yaml
from acapy_agent.config.error import ArgsParseError

LOGGER = logging.getLogger(__name__)


def parse_ledger_args(args):
    """Parse indy_ledger plugin arguments."""
    settings = {}
    if not args:
        raise ArgsParseError("No indy_ledger plugin arguments provided")

    update_pool_name = False
    write_ledger_specified = False

    if args.get("read_only_ledger"):
        LOGGER.debug("Setting read-only ledger")
        settings["read_only_ledger"] = True

    single_configured = True
    if args.get("genesis-url"):
        LOGGER.debug("Setting ledger.genesis_url = %s", args.get("genesis-url"))
        settings["ledger.genesis_url"] = args.get("genesis-url")
    elif args.get("genesis-file"):
        LOGGER.debug("Setting ledger.genesis_file = %s", args.get("genesis-file"))
        settings["ledger.genesis_file"] = args.get("genesis-file")
    elif args.get("genesis-transactions"):
        LOGGER.debug("Setting ledger.genesis_transactions")
        settings["ledger.genesis_transactions"] = args.get("genesis-transactions")
    else:
        LOGGER.debug("No genesis url, file, or transactions provided")
        single_configured = False

    multi_configured = False
    if args.get("genesis-transactions-list"):
        LOGGER.debug("Processing genesis_transactions_list")
        with open(args.get("genesis-transactions-list"), "r") as stream:
            # Load YAML configuration for multiple ledgers
            txn_config_list = yaml.safe_load(stream)
            ledger_config_list = []

            # Process each ledger configuration
            for txn_config in txn_config_list:
                # Check if this is a write ledger
                if txn_config.get("is_write", False):
                    write_ledger_specified = True

                # Ensure genesis information is provided
                has_genesis_info = (
                    "genesis_url" in txn_config
                    or "genesis_file" in txn_config
                    or "genesis_transactions" in txn_config
                )
                if not has_genesis_info:
                    raise ArgsParseError(
                        "No genesis information provided for write ledger"
                    )

                # Use ID as pool_name if pool_name not specified
                if "id" in txn_config and "pool_name" not in txn_config:
                    txn_config["pool_name"] = txn_config["id"]

                update_pool_name = True
                ledger_config_list.append(txn_config)

            # Ensure write ledger is specified unless in read-only mode
            if not write_ledger_specified and not args.get("read-only-ledger"):
                raise ArgsParseError(
                    "No write ledger genesis provided in multi-ledger config"
                )

            LOGGER.debug("Setting ledger.ledger_config_list")
            settings["ledger.ledger_config_list"] = ledger_config_list
            multi_configured = True

    if not (single_configured or multi_configured):
        raise ArgsParseError(
            "One of --genesis-url, --genesis-file, --genesis-transactions, "
            "or --genesis-transactions-list must be specified (unless "
            "--no-ledger is specified to explicitly configure aca-py to "
            "run with no ledger)."
        )

    if single_configured and multi_configured:
        raise ArgsParseError("Cannot configure both single- and multi-ledger.")

    if args.get("ledger-pool-name") and not update_pool_name:
        settings["ledger.pool_name"] = args.get("ledger-pool-name")
    if args.get("ledger-keepalive"):
        settings["ledger.keepalive"] = args.get("ledger-keepalive")
    if args.get("ledger-socks-proxy"):
        settings["ledger.socks_proxy"] = args.get("ledger-socks-proxy")
    if args.get("accept-taa"):
        settings["ledger.taa_acceptance_mechanism"] = args.get("accept-taa")[0]
        settings["ledger.taa_acceptance_version"] = args.get("accept-taa")[1]

    return settings
