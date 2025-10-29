# aries-acapy-cache-redis
ACA-Py Redis Base Cache Plugin
=======================================

ACA-Py uses a modular cache layer to story key-value pairs of data. The purpose
of this plugin is to allow ACA-Py to use Redis as the storage medium for it's
caching needs.

_**Why might I need this plugin?**_
When demand increases, horizontal scaling helps relieve the stress on systems
by spreading the load across multiple systems. Depending on the algorithm used
to distribute requests across a cluster, the requests from an individual
connection may end up on different hosts partway though an exchange of
information. Normally, ACA-Py caches certain key data *in-memory* to create
some relief on the database. This has the unintended side-effect of the cache
getting out of data if the requests switch between machines. Using an external
system, such as Redis, to manage the cache can ensure that it stays up-to-date
amongst machines and continues to provide some relief to the database.


## Installation and Usage

### With Docker (Recommended)
Running the plugin with docker is simple and straight-forward. There is an
example [docker-compose.yml](./docker-compose.yml) file in the root of the
project that launches both ACA-Py and an accompanying Redis instance. Running
it is as simple as:

```sh
$ docker-compose up --build
```

To launch ACA-Py with an accompanying redis cluster of 6 nodes [3 primararies and 3 replicas], please refer to example [docker-compose.cluster.yml](./docker-compose.cluster.yml) and run the following:

Note: Cluster requires external docker network with specified subnet

```sh
$ docker network create --subnet=172.28.0.0/24 `network_name`
$ export REDIS_PASSWORD=" ... As specified in redis_cluster.conf ... "
$ export NETWORK_NAME="`network_name`"
$ docker-compose -f docker-compose.cluster.yml up --build
```

If you are looking to integrate the plugin with your own projects, it is highly
recommended to take a look at both [docker-compose.yml](./docker-compose.yml)
and the [ACA-Py default.yml](./docker/default.yml) files for a single redis host setup or at both [docker-compose.cluster.yml](./docker-compose.cluster.yml.yml)
and the [ACA-Py default_cluster.yml](./docker/default_cluster.yml) files for a redis cluster setup to help kickstart your
project.

### Without Docker

First, install this plugin into your environment.

```sh
$ poetry install
$ poetry shell
```

Launch a local redis server for development.

```sh
$ docker run -d -v `pwd`/redis.conf:/usr/local/etc/redis/redis.conf \
  --name redis_cache -p 6379:6379 redis redis-server /usr/local/etc/redis/
```

When starting up ACA-Py, load the plugin along with any other startup
parameters. *Note: You may need to change the redis hostname*

```sh
$ aca-py start --arg-file ./docker/default.yml
```

For redis cluster, please review `redis_cluster.conf` and `default_cluster.yml`. Basically `defualt_cluster.yml` includes connection string of a cluster node as `redis_cache.connection`.

For manual testing with a second ACA-Py instance, you can run the following.

```sh
$ aca-py start --arg-file ./docker/default.yml --admin 0.0.0.0 3003 \
  -it http 0.0.0.0 3002 -e http://localhost:3002 
```

### Configuration
Within the [default.yml](./docker/default.yml) file, all configuration for the
Redis Base Cache Plugin resides within the `plugin-config-value` block. The
configuration options are defined as follows:
 - `redis_cache.connection` The host connection URI for the Redis server. A
	 different DB can be selected by adding a `/0` or `/1` to the end of the URI
	 - The URI may start with `rediss://` for SSL connections and `redis://` for
		 non-SSL connections
 - `redis_cache.max_connections` The maximum number of connections to Redis
	 that the connection pool may allocate
 - `redis_cache.credentials.username` Username for the Redis server (if not
	 using the default user)
 - `redis_cache.credentials.password` The password for the Redis server/user
 - `redis_cache.ssl.cacerts` Path to the root CA information. Useful for when
	 using self-signed certificates.

## Running The Integration Tests

### Single redis host
```sh
$ docker-compose -f int/docker-compose.yml run tests-host
```

### Redis cluster
Cluster requires external docker network with specified subnet
```sh
$ docker network create --subnet=172.28.0.0/24 `network_name`
$ export REDIS_PASSWORD=" ... As specified in redis_cluster.conf ... "
$ export NETWORK_NAME="`network_name`"
$ docker-compose -f int/docker-compose.yml run tests-cluster
```
