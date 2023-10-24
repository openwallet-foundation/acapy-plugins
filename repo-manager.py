from fileinput import FileInput
import os
import shutil


def replace_plugin_tag(path: str, plugin_name: str, plugin_version_path: str = None):
    with open(path, 'r') as file:
        filedata = file.read()
    filedata = filedata.replace('base_empty_plugin', plugin_name)
    if plugin_version_path:
        filedata = filedata.replace('base_plugin_version', plugin_version_path)
    with open(path, 'w') as file:
        file.write(filedata)


selection = input(
    "What would you like to do? \n (1) Create a new plugin \n (2) Update all plugin common dependencies \n (3) Update plugin common files \n (4) Exit \n\nInput:  ")

print("You selected: " + selection)

if selection == "1":
    # Create a new plugin
    print("Creating a new plugin")
    plugin_name = input("Enter the plugin name: ")
    plugin_version = str(
        input("Enter the plugin version (default is 0.1.0): ") or "0.1.0")
    plugin_version_path = str(
        input("Enter the plugin version path (default is v1_0): ") or "v1_0")
    os.makedirs(f'./{plugin_name}/{plugin_name}/{plugin_version_path}')
    shutil.copytree('./base_empty_plugin/.devcontainer',
                    f'./{plugin_name}/.devcontainer')
    replace_plugin_tag(
        f'./{plugin_name}/.devcontainer/devcontainer.json', plugin_name)
    shutil.copytree('./base_empty_plugin/.vscode',
                    f'./{plugin_name}/.vscode')
    replace_plugin_tag(f'./{plugin_name}/.vscode/launch.json', plugin_name)
    shutil.copytree('./base_empty_plugin/docker', f'./{plugin_name}/docker')
    replace_plugin_tag(
        f'./{plugin_name}/docker/default.yml', plugin_name, plugin_version_path)
    replace_plugin_tag(f'./{plugin_name}/docker/Dockerfile', plugin_name)
    replace_plugin_tag(
        f'./{plugin_name}/docker/integration.yml', plugin_name, plugin_version_path)
    shutil.copytree('./base_empty_plugin/integration',
                    f'./{plugin_name}/integration')
    with FileInput(f'./{plugin_name}/integration/pyproject.toml', inplace=True) as file:
        for line in file:
            if line.startswith('name'):
                print(line.replace('base_empty_plugin', plugin_name), end='')
            elif line.startswith('version'):
                print(f'version = "{plugin_version}"', end='\n')
            else:
                print(line, end='')
