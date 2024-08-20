"""Utilities for redis_queue module."""

import asyncio
import base64
import datetime
import json
import logging
from typing import List, Union

from redis.asyncio import RedisCluster

LOGGER = logging.getLogger(__name__)


def str_to_datetime(datetime_str):
    """Convert datetime string to datetime object."""
    return datetime.datetime.strptime(datetime_str, "%Y-%m-%dT%H:%M:%SZ")


def curr_datetime_to_str():
    """Convert current datetime to string."""
    return (datetime.datetime.now()).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_timedelta_seconds(rec_datetime):
    """Get timedelta in seconds."""
    datetime_now = str_to_datetime(curr_datetime_to_str())
    timedelta_seconds = datetime_now - rec_datetime
    return timedelta_seconds.total_seconds()


def b64_to_bytes(val: Union[str, bytes], urlsafe=True) -> bytes:
    """Convert a base 64 string to bytes."""
    if isinstance(val, str):
        val = val.encode("ascii")
    if urlsafe:
        missing_padding = len(val) % 4
        if missing_padding:
            val += b"=" * (4 - missing_padding)
        return base64.urlsafe_b64decode(val)
    return base64.b64decode(val)


def _recipients_from_packed_message(packed_message: bytes) -> List[str]:
    """Inspect the header of the packed message and extract the recipient key."""
    try:
        wrapper = json.loads(packed_message)
    except Exception as err:
        raise ValueError("Invalid packed message") from err

    recips_json = b64_to_bytes(wrapper["protected"], urlsafe=True).decode("ascii")
    try:
        recips_outer = json.loads(recips_json)
    except Exception as err:
        raise ValueError("Invalid packed message recipients") from err

    return [recip["header"]["kid"] for recip in recips_outer["recipients"]]


async def get_recip_keys_list_for_uid(redis: RedisCluster, plugin_uid: bytes):
    """Get recip_keys list associated with plugin UID."""
    recip_keys_encoded = await redis.hget("uid_recip_keys_map", plugin_uid)
    if not recip_keys_encoded:
        return []
    inbound_msg_keys = json.loads(b64_to_bytes(recip_keys_encoded).decode())
    return inbound_msg_keys


async def get_new_valid_uid(redis: RedisCluster, to_ignore_uid: bytes = None):
    """Get a new plugin UID for recip_key assignment/reassignment."""
    new_uid = None
    uid_not_selected = False
    while not uid_not_selected:
        if not await redis.get("round_robin_iterator"):
            await redis.set("round_robin_iterator", 0)
        next_iter = int((await redis.get("round_robin_iterator")).decode())
        uid_list = await redis.hkeys("uid_recip_keys_map")
        if to_ignore_uid and len(uid_list) > 1:
            try:
                uid_list.remove(to_ignore_uid)
            except (KeyError, ValueError):
                pass
        if len(uid_list) == 0:
            LOGGER.error("No plugin instance available for assignment")
            await redis.ping(target_nodes=RedisCluster.PRIMARIES)
            await asyncio.sleep(3)
            continue
        try:
            new_uid = uid_list[next_iter]
        except IndexError:
            new_uid = uid_list[0]
        next_iter = next_iter + 1
        if next_iter < len(uid_list):
            await redis.set("round_robin_iterator", next_iter)
        else:
            await redis.set("round_robin_iterator", 0)
        uid_not_selected = True
    return new_uid


async def assign_recip_key_to_new_uid(redis: RedisCluster, recip_key: str):
    """Assign recip_key to a new plugin UID."""
    new_uid = await get_new_valid_uid(redis)
    recip_key_encoded = recip_key.encode("utf-8")
    await redis.hset("recip_key_uid_map", recip_key_encoded, new_uid)
    recip_keys_list = await get_recip_keys_list_for_uid(redis, new_uid)
    recip_keys_set = set(recip_keys_list)
    if recip_key not in recip_keys_set:
        recip_keys_set.add(recip_key)
        new_recip_keys_set = base64.urlsafe_b64encode(
            json.dumps(list(recip_keys_set)).encode("utf-8")
        ).decode()
        await redis.hset("uid_recip_keys_map", new_uid, new_recip_keys_set)
    uid_recip_key = f"{new_uid.decode()}_{recip_key}".encode("utf-8")
    await redis.hset("uid_recip_key_pending_msg_count", uid_recip_key, 0)
    return new_uid


async def reassign_recip_key_to_uid(redis: RedisCluster, old_uid: bytes, recip_key: str):
    """Reassign recip_key from old_uid to a new plugin UID."""
    new_uid = await get_new_valid_uid(redis, old_uid)
    recip_key_encoded = recip_key.encode("utf-8")
    old_recip_keys_list = await get_recip_keys_list_for_uid(redis, old_uid)
    new_recip_keys_list = await get_recip_keys_list_for_uid(redis, new_uid)
    old_recip_keys_set = set(old_recip_keys_list)
    try:
        old_recip_keys_set.remove(recip_key)
    except (KeyError, ValueError):
        pass
    await redis.hset(
        "uid_recip_keys_map",
        old_uid,
        base64.urlsafe_b64encode(
            json.dumps(list(old_recip_keys_set)).encode("utf-8")
        ).decode(),
    )
    old_uid_recip_key = f"{old_uid.decode()}_{recip_key}".encode("utf-8")
    old_pending_msg_count = await redis.hget(
        "uid_recip_key_pending_msg_count", old_uid_recip_key
    )
    await redis.hdel("uid_recip_key_pending_msg_count", old_uid_recip_key)
    await redis.hset("recip_key_uid_map", recip_key_encoded, new_uid)
    new_recip_keys_set = set(new_recip_keys_list)
    new_recip_keys_set.add(recip_key)
    new_recip_keys_list = base64.urlsafe_b64encode(
        json.dumps(list(new_recip_keys_set)).encode("utf-8")
    ).decode()
    await redis.hset("uid_recip_keys_map", new_uid, new_recip_keys_list)
    new_uid_recip_key = f"{new_uid.decode()}_{recip_key}".encode("utf-8")
    if old_pending_msg_count:
        await redis.hincrby(
            "uid_recip_key_pending_msg_count",
            new_uid_recip_key,
            int(old_pending_msg_count.decode()),
        )
    return new_uid


async def process_payload_recip_key(
    redis: RedisCluster, payload: Union[str, bytes], topic: str
):
    """Process payload and recip_key and return topic and message."""
    recip_key_in = ",".join(_recipients_from_packed_message(payload))
    recip_key_in_encoded = recip_key_in.encode()
    message = str.encode(
        json.dumps(
            {
                "payload": base64.urlsafe_b64encode(payload).decode(),
            }
        ),
    )
    if await redis.hexists("recip_key_uid_map", recip_key_in_encoded):
        plugin_uid = await redis.hget("recip_key_uid_map", recip_key_in_encoded)
    else:
        plugin_uid = await assign_recip_key_to_new_uid(redis, recip_key_in)
    last_accessed_map_value = await redis.hget("uid_last_access_map", plugin_uid)
    stale_uid_check = False
    if not last_accessed_map_value:
        stale_uid_check = True
    elif last_accessed_map_value and (
        get_timedelta_seconds(str_to_datetime(last_accessed_map_value.decode())) >= 15
    ):
        stale_uid_check = True
    if stale_uid_check:
        old_uid = plugin_uid
        assigned_recip_key_list = await get_recip_keys_list_for_uid(redis, old_uid)
        reassign_uid = False
        for recip_key in assigned_recip_key_list:
            uid_recip_key = f"{old_uid.decode()}_{recip_key}".encode("utf-8")
            enc_uid_recip_key_msg_cnt = await redis.hget(
                "uid_recip_key_pending_msg_count", uid_recip_key
            )
            if (
                enc_uid_recip_key_msg_cnt is not None
                and int(enc_uid_recip_key_msg_cnt.decode()) >= 1
            ):
                reassign_uid = True
                break
        if reassign_uid:
            for recip_key in assigned_recip_key_list:
                new_uid = await reassign_recip_key_to_uid(redis, old_uid, recip_key)
                if recip_key == recip_key_in:
                    plugin_uid = new_uid
            updated_recip_keys_list = await get_recip_keys_list_for_uid(redis, old_uid)
            if len(updated_recip_keys_list) == 0:
                await redis.hdel(
                    "uid_recip_keys_map",
                    old_uid,
                )
    uid_recip_key = f"{plugin_uid.decode()}_{recip_key_in}".encode("utf-8")
    await redis.hincrby("uid_recip_key_pending_msg_count", uid_recip_key, 1)
    return (f"{topic}_{recip_key_in}", message)
