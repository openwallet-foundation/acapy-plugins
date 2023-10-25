from fileinput import FileInput
import os
import shutil


class PluginInfo:
    def __init__(
        self,
        name: str,
        version: str,
        description: str,
        dependencies: list = [],
        dev_dependencies: list = []
    ):
        self.name = name
        self.version = version
        self.description = description
        self.dependencies = dependencies
        self.dev_dependencies = dev_dependencies


def replace_plugin_tag(path: str, info: PluginInfo):
    print("**********************")
    with open(path, 'r') as file:
        filedata = file.read()
    print(filedata)
    filedata = filedata.replace('plugin_globals', info.name)
    with open(path, 'w') as file:
        file.write(filedata)


# def print_deps(common_deps: list, plugin_deps: list):
#     common_dep_names = []
#     for dep in common_deps:
#         common_dep_names.append(dep.split('=')[0].strip())
#         print(dep, end='\n')
#     for dep in plugin_deps:
#         if dep.split('=')[0].strip() not in common_dep_names:
#             print(dep, end='\n')


def is_blank_line(line: str) -> bool:
    return len(line.strip()) == 0


def update_common_dependencies(path: str, info: PluginInfo):
    replace_plugin_tag(path, info)
    # deps = extract_common_dependencies(path)
    # dep_section = False
    # dev_dep_section = False
    with FileInput(path, inplace=True) as file:
        for line in file:
            if line.startswith('version'):
                print(f'version = "{info.version}"', end='\n')
            elif line.startswith('description'):
                print(f'description = "{info.description}"', end='\n')
            # elif line.startswith('authors'):
            #     print(f'authors = {info.authors}', end='\n')
            # elif dep_section:
            #     if is_blank_line(line):
            #         print_deps(
            #             common_deps=deps['dependencies'], plugin_deps=info.dependencies)
            #         dep_section = False
            #         print(line, end='')
            #     else:
            #         print("", end='')
            # elif dev_dep_section:
            #     if is_blank_line(line):
            #         print_deps(
            #             common_deps=deps['dev_dependencies'], plugin_deps=info.dev_dependencies)
            #         dev_dep_section = False
            #         print(line, end='')
            #     else:
            #         print("", end='')
            # elif line.startswith('[tool.poetry.dependencies]'):
            #     print(line, end='')
            #     dep_section = True
            # elif line.startswith('[tool.poetry.dev-dependencies]'):
            #     print(line, end='')
            #     dev_dep_section = True
            # else:
            #     print(line, end='')


def replace_meta_data(path: str, info: PluginInfo):
    replace_plugin_tag(path, info)
    # with FileInput(path, inplace=True) as file:
    #     for line in file:
    #         if line.startswith('version'):
    #             print(f'version = "{info.version}"', end='\n')
    #         elif line.startswith('description'):
    #             print(f'description = "{info.description}"', end='\n')
    #         # elif line.startswith('authors'):
    #         #     print(f'authors = {info.authors}', end='\n')


def copy_all_common_files_for_new_plugin(info: PluginInfo):
    shutil.copytree(
        './plugin_globals/docker',
        f'./{info.name}/docker'
    )
    shutil.copytree(
        './plugin_globals/integration',
        f'./{info.name}/integration'
    )
    shutil.copyfile(
        './plugin_globals/pyproject.toml',
        f'./{info.name}/pyproject.toml'
    )
    shutil.copyfile(
        './plugin_globals/README.md',
        f'./{info.name}/README.md'
    )
    shutil.copyfile(
        './plugin_globals/definition.py',
        f'./{info.name}/{info.name}/definition.py'
    )
    replace_plugin_tag(
        f'./{info.name}/docker/default.yml', info)
    replace_plugin_tag(
        f'./{info.name}/docker/Dockerfile', info)
    replace_plugin_tag(
        f'./{info.name}/docker/integration.yml', info)
    # write_plugin_specific_deps(info)
    replace_meta_data(
        f'./{info.name}/integration/pyproject.toml', info)
    replace_meta_data(
        f'./{info.name}/pyproject.toml', info)


def copy_common_files_for_all_plugins(info: PluginInfo):
    shutil.copytree(
        './plugin_globals/.devcontainer',
        f'./{info.name}/.devcontainer',
        dirs_exist_ok=True
    )
    shutil.copytree(
        './plugin_globals/.vscode',
        f'./{info.name}/.vscode',
        dirs_exist_ok=True
    )
    replace_plugin_tag(
        f'./{info.name}/.devcontainer/devcontainer.json', info)
    replace_plugin_tag(
        f'./{info.name}/.vscode/launch.json', info)


def copy_and_tag_shared_files(info: PluginInfo, new_plugin: bool = True):
    if new_plugin:
        copy_all_common_files_for_new_plugin(info)
    # copy_common_files_for_all_plugins(info)


def process_deps_from_file(filedata: list, deps: list, i: int):
    i += 1
    line = filedata[i]
    while not is_blank_line(line):
        deps.append(line)
        i += 1
        line = filedata[i]
    return i


def process_meta_data_from_file(filedata: list, i: int, key: str) -> str:
    extracted_str = ""
    line = filedata[i]
    while not is_blank_line(line):
        extracted_str += line
        i += 1
        line = filedata[i]
    return i, extracted_str.replace(f'{key} = ', '').strip('"')


def extract_common_dependencies(path: str):
    dependencies = []
    dev_dependencies = []
    with open(path, 'r') as file:
        filedata = file.read()
    filedata = filedata.split('\n')
    for i in range(len(filedata)):
        line = filedata[i]
        if line.startswith('[tool.poetry.dependencies]'):
            i = process_deps_from_file(filedata, deps=dependencies, i=i)
        if line.startswith('[tool.poetry.dev-dependencies]'):
            i = process_deps_from_file(filedata, deps=dev_dependencies, i=i)
    return {
        'dependencies': dependencies,
        'dev_dependencies': dev_dependencies
    }


def replace_global_dependencies(name: str):
    global_dependencies = []
    global_dev_dependencies = []
    global_integration_deps = []
    plugin_dependencies = []
    plugin_dev_dependencies = []
    plugin_integration_deps = []
    with open(f'./plugin_globals/pyproject.toml', 'r') as file:
        filedata = file.read()
    filedata = filedata.split('\n')
    for i in range(len(filedata)):
        line = filedata[i]
        if line == '[tool.poetry.dependencies]':
            while not is_blank_line(line):
                i += 1
                line = filedata[i]
                global_dependencies.append(line)
        if line == '[tool.poetry.dev-dependencies]':
            while not is_blank_line(line):
                i += 1
                line = filedata[i]
                global_dev_dependencies.append(line)
        if line == '[tool.poetry.group.integration.dependencies]':
            while not is_blank_line(line):
                i += 1
                line = filedata[i]
                global_integration_deps.append(line)

    with open(f'./{name}/pyproject.toml', 'r') as file:
        filedata = file.read()
    filedata = filedata.split('\n')
    for i in range(len(filedata)):
        line = filedata[i]
        if line == '[tool.poetry.dependencies]':
            while not is_blank_line(line):
                i += 1
                line = filedata[i]
                plugin_dependencies.append(line)
        if line == '[tool.poetry.dev-dependencies]':
            while not is_blank_line(line):
                i += 1
                line = filedata[i]
                plugin_dev_dependencies.append(line)
        if line == '[tool.poetry.group.integration.dependencies]':
            while not is_blank_line(line):
                i += 1
                line = filedata[i]
                plugin_integration_deps.append(line)
    print(global_dependencies, plugin_dependencies)


def is_plugin_dir(plugin_name: str) -> bool:
    # If there is a drirectory which is not a plugin it should be ignored here
    return os.path.isdir(plugin_name) and plugin_name != 'plugin_globals' and not plugin_name.startswith('.')


# Check poetry is available
print("Checking poetry is available...")
response = os.system('which poetry')
if response == "":
    print("Poetry is not available. Please install poetry.")
    exit(1)

msg = """
    What would you like to do? 
    (1) Create a new plugin
    (2) Update all plugin common dependencies 
    (3) Update all plugin common files 
    (4) Exit \n\nInput:  """
selection = input(msg)

if selection == "1":
    # Create a new plugin
    msg = """Creating a new plugin: This will create a blank plugin with all the common files and folders needed to get started developing and testing."""
    print(msg)
    name = input(
        "Enter the plugin name (recommended to use snake_case): ")
    if name == "":
        print("You must enter a plugin name")
        exit(1)
    version = str(
        input("Enter the plugin version (default is 0.1.0): ") or "0.1.0")
    description = input("Enter the plugin description (default is ''): ") or ""

    plugin_info = PluginInfo(name, version, description)
    os.makedirs(f'./{name}/{name}/v1_0')
    copy_and_tag_shared_files(info=plugin_info)

    os.system(f'cd {name} && poetry install --no-root')

elif selection == "2":
    # Update all plugin common dependencies
    msg = """Updating all plugin common dependencies: This will take the common dependencies from the plugin_globals and combine them with the dependencies from the plugins plugin-specific.deps file. Add them to the plugins pyproject.toml file and install and update the lock file \n"""
    print(msg)
    for plugin_name in os.listdir('./'):
        if is_plugin_dir(plugin_name):
            print(f'Updating {plugin_name}\n')
            plugin_info = replace_global_dependencies(plugin_name)
            os.system(
                f'cd {plugin_name} && rm poetry.lock && poetry install')

elif selection == "3":
    # Update all plugin common files
    msg = """Updating all plugin common files: This will take the common files from the plugin_globals and copy them into each plugin. It will also update the files with the plugin name and version"""
    print(msg)
    for plugin_name in os.listdir('./'):
        if is_plugin_dir(plugin_name):
            print(f'Updating {plugin_name}\n')
            # plugin_info = extract_plugin_info(plugin_name)
            # plugin_info.name = plugin_name
            # copy_and_tag_shared_files(info=plugin_info, new_plugin=False)
