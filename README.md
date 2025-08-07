# ACA-Py Plugins

This repository contains approved and tested plugins for [ACA-Py]. This is to encourage collaboration and sharing of useful features not directly included in ACA-Py.

[ACA-Py]: https://aca-py.org

## Developer Notes

The easiest way to develop and test ACA-Py plugins is to use the DevContainer configured in this repository.

- Open devcontainer in VS Code
- Python and all dependencies will be loaded
- Poetry will be loaded and configured, dependencies will be installed
- Docker and Docker Compose will be available

## Repo Management Script

A script was developed to help with maintenance of the repo called `repo_manager.py`. To run it you need a current version of poetry and python available.

Run `python repo_manager.py` and you will be met with a number of options. Run the options as needed.

- (1) Is used for starting or adding a new plugin. It will generate all the
  common scaffolding for a plugin which has the expected format.
- (2) Is used for updating and changing common poetry dependencies and
  configurations. It takes the poetry sections in the `pyproject.toml` files
  from the `plugin_globals` directory and combines them with the local plugin
  poetry sections. For the dependencies the common will be overridden by the
  globals. The other config sections will be replaced by the global configs.
  Then the lock files will be removed and re-installed.
- (3) Is used for updating the plugin versions in the `plugin_globals`
  directory. It will update the versions of the plugins in the `plugin_globals`
  directory to the latest version on the main branch of the plugin repo. It will
  also update the `plugin_globals` directory to the latest version on the main
  branch of the plugin repo.
- (4) This option is used by the CI/CD release pipeline. It updates the release
  notes and the individual plugins with a new version of ACA-Py.
- (5) This option is also used by the CI/CD release pipeline. It gets any
  plugins that have succeeded the tests after a new version of ACA-Py
  has been released if their changes were not reverted than the plugin has been
  updated to the new version of ACA-Py.
- (6) This option will run a general update for all poetry lock files in all
  plugins.
- (7) This option is used for upgrading a particular library for all plugins.
  It's useful for when you don't want to do a general upgrade for every library. 

## Lite plugins

Sometimes is desirable to have a plugin that doesn't need integration tests or
extra scaffolding. However, we need a way to avoid these plugins running
integration tests in the CI/CD pipeline. To do this, we can simply add the
plugin name to the `lite_plugins` file, a line-separated list of plugin names.

## Plugin Documentation

Plugin developers **SHOULD** describe what the plugin does, any limitations (ex
only in multitenant mode), any known issues interacting with other plugins, etc.
Full documentation including a plugin_config sample should be provided.

This documentation should be provided in your plugin root as a README.md file,
with at least a `Description` and `Configuration` section.

## Build and Run

Each plugin (that is not a [Lite Plugin](#lite-plugins)) **MUST** include a
Dockerfile (such as [Dockerfile](https://github.com/openwallet-foundation/acapy-plugins/blob/main/basicmessage_storage/docker/Dockerfile)) to
run integration tests. This image is not intended for production as it copies
the plugin source and loads its dependencies (including ACA-Py) along with a
simplistic ACA-Py configuration file, (such as
[default.yml](https://github.com/openwallet-foundation/acapy-plugins/blob/main/basicmessage_storage/docker/default.yml)).

## Run and Debug

In the devcontainer, we can run an ACA-Py instance with our plugin source loaded
and set breakpoints for debug (see `launch.json`).

To run your ACA-Py code in debug mode, go to the `Run and Debug` view, select
"Run/Debug Plugin" and click `Start Debugging (F5)`. Using the `default.yml` for
the plugin (such as [default.yml](https://github.com/openwallet-foundation/acapy-plugins/blob/main/basicmessage_storage/docker/default.yml)),
your agent swagger is available at http://localhost:3001/api/doc.

## Testing

For the plugin to be accepted into this repo it must have adequate testing.

### Unit Testing:

- There should be adequate unit testing coverage. A coverage report is created when `poetry run pytest .` in ran from the devcontainer. A good mark to aim for is 90% but the quality of the tests on critical sections is more important than coverage percentage.
- Mocking can be challenging. Study the existing plugins in this repo and ACA-Py in general for good examples of mocks and fixtures.
- Put your unit tests in a tests folder in your plugin version path and name all files and test with the `test_` prefix.

### Integration Testing:

- Plugins **SHOULD** have a suite of integration tests. The base suite will be
  created for your plugin after running the updater script. Plugins that don't
  have integrations must be flagged as being a [Lite Plugin](#lite-plugins).
- An Integration `README` (such as [integration
  tests](https://github.com/openwallet-foundation/acapy-plugins/blob/main/basicmessage_storage/integration/README.md)) **SHOULD** describe the
  set of integration tests. When you generate a new plugin, you should have
  everything you need to start integration testing and a sample test will be
  provided.

## Deploy

For production use, plugins should be installed as libraries to an ACA-Py image.

This requires having a Dockerfile and a config file for your agent.

Example Dockerfile:

```yaml

FROM ghcr.io/openwallet-foundation/acapy:py3.12-1.1.0

USER root

# install plugins as binaries
RUN pip install git+https://github.com/openwallet-foundation/acapy-plugins@main#subdirectory=basicmessage_storage
RUN pip install git+https://github.com/openwallet-foundation/acapy-plugins@main#subdirectory=connection_update

USER $user
COPY ./configs configs

CMD ["ACA-Py"]

```

Example config file (local single tenant):

``` yaml

label: plugins-agent

admin-insecure-mode: true
admin: [0.0.0.0, 9061]

inbound-transport:
   - [http, 0.0.0.0, 9060]
outbound-transport: http
endpoint: http://host.docker.internal:9060

genesis-url: http://test.bcovrin.vonx.io/genesis

emit-new-didcomm-prefix: true
wallet-type: askar
wallet-storage-type: default

auto-provision: true
debug-connections: true
auto-accept-invites: true
auto-accept-requests: true
auto-ping-connection: true
auto-respond-messages: true

log-level: info

plugin:
  - basicmessage_storage.v1_0
  - connection_update.v1_0

```

Now you can deploy a agent with as many plugins as you want as long as they are declared in your build config file and installed.

``` bash

docker build -f <Dockerfile> --tag acapy_plugins .
docker run -it -p 9060:9060 -p 9061:9061 --rm acapy_plugins start --arg-file=<config-file> -->

```
