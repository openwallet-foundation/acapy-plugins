import os
import shutil
from typing import Optional
from enum import Enum

GLOBAL_PLUGIN_DIR = 'plugin_globals' 

class PluginInfo:
    def __init__(
        self,
        name: str,
        version: Optional[str] = None,
        description: Optional[str] = None,
    ):
        self.name = name
        self.version = version
        self.description = description


class MangagedPoetrySections:
    META = '[tool.poetry]'
    DEPS = '[tool.poetry.dependencies]'
    INT_DEPS = '[tool.poetry.dev-dependencies]'
    DEV_DEPS = '[tool.poetry.group.integration.dependencies]'
    RUFF = '[tool.ruff]'
    RUFF_LINT = '[tool.ruff.lint]'
    RUFF_FILES = '[tool.ruff.per-file-ignores]'
    PYTEST = '[tool.pytest.ini_options]'
    COVERAGE = '[tool.coverage.run]'
    COVERAGE_REPORT = '[tool.coverage.report]'
    COVERAGE_XML = '[tool.coverage.xml]'
    BUILD = '[build-system]'


class Sections:
    def __init__(self):
        self.meta = []
        self.deps = []
        self.dev_deps = []
        self.int_deps = []
        self.ruff = []
        self.ruff_lint = []
        self.ruff_files = []
        self.pytest = []
        self.coverage = []
        self.coverage_report = []
        self.coverage_xml = []
        self.build = []

class NEW_PLUGIN_FOLDERS(Enum):
    DOCKER = 'docker'
    INTEGRATION = 'integration'

class NEW_PLUGIN_FILES(Enum):
    PYPROJECT = 'pyproject.toml'
    README = 'README.md'
    DEFINITION = 'definition.py'

class COMMON_DEV_FOLDERS(Enum):
    DEVCONTAINER = '.devcontainer'
    VSCODE = '.vscode'

class TAGGED_FILES(Enum):
    DOCKER_DEFAULT = 'docker/default.yml'
    DOCKERFILE = 'docker/Dockerfile'
    DOCKER_INTEGRATION = 'docker/integration.yml'
    PYPROJECT = 'pyproject.toml'
    PYPROJECT_INTEGRATION = 'integration/pyproject.toml'
    DEVCONTAINER = '.devcontainer/devcontainer.json'
    VSCODE = '.vscode/launch.json'


def replace_plugin_tag(path: str, info: PluginInfo):
    with open(path, 'r') as file:
        filedata = file.read()
    filedata = filedata.replace(GLOBAL_PLUGIN_DIR, info.name)
    with open(path, 'w') as file:
        file.write(filedata)


def is_blank_line(line: str) -> bool:
    return len(line.strip()) == 0


def copy_all_common_files_for_new_plugin(info: PluginInfo) -> None:
    for folder in list(NEW_PLUGIN_FOLDERS):
        shutil.copytree(
            f'./{GLOBAL_PLUGIN_DIR}/{folder.value}',
            f'./{info.name}/{folder.value}'
        )
    for file in list(NEW_PLUGIN_FILES):
        shutil.copyfile(
            f'./{GLOBAL_PLUGIN_DIR}/{file.value}',
            f'./{info.name}/{file.value}'
        )

def copy_common_files_for_all_plugins(info: PluginInfo) -> None:
    for folder in list(COMMON_DEV_FOLDERS):
        shutil.copytree(
            f'./{GLOBAL_PLUGIN_DIR}/{folder.value}',
            f'./{info.name}/{folder.value}',
            dirs_exist_ok=True
        )
    for file in list(TAGGED_FILES):
        replace_plugin_tag(
            f'./{info.name}/{file.value}', info)


def copy_and_tag_shared_files(info: PluginInfo, new_plugin: bool = True):
    if new_plugin:
        copy_all_common_files_for_new_plugin(info)
    copy_common_files_for_all_plugins(info)


def combine_dependenices(plugin_dependencies, global_dependencies) -> None:
    """Add the plugin dependencies to the global dependencies if they are plugin specific."""
    for p_dep in plugin_dependencies:
        if (p_dep.split('=')[0].strip() not in [g_dep.split('=')[0].strip() for g_dep in global_dependencies]):
            global_dependencies.append(p_dep)
    global_dependencies.sort()


def get_section(i: int, filedata: list, arr: list) -> int:
    """Put the section into the array and return the number of lines in the section."""
    j = i
    while j < len(filedata) and not is_blank_line(filedata[j]):
        arr.append(filedata[j])
        j += 1
    return j - i


def extract_common_sections(filedata: str, sections: Sections) -> None:
    """Go through the file by line and extract the section into the sections object."""
    filedata = filedata.split('\n')
    for i in range(len(filedata)):
        line = filedata[i]
        if line == MangagedPoetrySections.META:
            i += get_section(i + 1, filedata, sections.meta)
        if line == MangagedPoetrySections.DEPS:
            i += get_section(i + 1, filedata, sections.deps)
        if line == MangagedPoetrySections.DEV_DEPS:
            i += get_section(i + 1, filedata, sections.dev_deps)
        if line == MangagedPoetrySections.INT_DEPS:
            i += get_section(i + 1, filedata, sections.int_deps)
        if line == MangagedPoetrySections.RUFF:
            i += get_section(i + 1, filedata, sections.ruff)
        if line == MangagedPoetrySections.RUFF_LINT:
            i += get_section(i + 1, filedata, sections.ruff_lint)
        if line == MangagedPoetrySections.RUFF_FILES:
            i += get_section(i + 1, filedata, sections.ruff_files)
        if line == MangagedPoetrySections.PYTEST:
            i += get_section(i + 1, filedata, sections.pytest)
        if line == MangagedPoetrySections.COVERAGE:
            i += get_section(i + 1, filedata, sections.coverage)
        if line == MangagedPoetrySections.COVERAGE_REPORT:
            i += get_section(i + 1, filedata, sections.coverage_report)
        if line == MangagedPoetrySections.COVERAGE_XML:
            i += get_section(i + 1, filedata, sections.coverage_xml)
        if line == MangagedPoetrySections.BUILD:
            i += get_section(i + 1, filedata, sections.build)


def get_section_output(i: int, content: list, output: list, section: list) -> int:
    """
    Get a config section based off of an empty line of length of file.
    Args:
        i: The current line number
        content: The file content
        output: The output list
        section: The section to process

    Returns: The number of lines in the section
    """
    j = i
    output.append(content[j])
    while (j < len(content) - 1 and not is_blank_line(content[j])):
        j += 1
    while (len(section) > 0):
        output.append(section.pop(0) + '\n')
    output.append('\n')
    return j - i


def get_and_combine_main_poetry_sections(name: str) -> (Sections, Sections):
    """Get the global main sections and combine them with the plugin specific sections."""
    global_sections = Sections()
    plugin_sections = Sections()

    with open(f'./{GLOBAL_PLUGIN_DIR}/{TAGGED_FILES.PYPROJECT.value}', 'r') as file:
        filedata = file.read()
        extract_common_sections(filedata, global_sections)

    with open(f'./{name}/{TAGGED_FILES.PYPROJECT.value}', 'r') as file:
        filedata = file.read()
        extract_common_sections(filedata, plugin_sections)

    combine_dependenices(plugin_sections.deps, global_sections.deps)
    combine_dependenices(plugin_sections.dev_deps,
                         global_sections.dev_deps)
    combine_dependenices(plugin_sections.int_deps,
                         global_sections.int_deps)
    return global_sections, plugin_sections


def process_main_config_sections(name: str, plugin_sections: Sections, global_sections: Sections) -> None:
    """Process the main config sections and write them to the plugins pyproject.toml file."""
    with open(f'./{GLOBAL_PLUGIN_DIR}/{TAGGED_FILES.PYPROJECT.value}', 'r') as in_file:
        content = in_file.readlines()

    output = []
    with open(f'./{name}/{TAGGED_FILES.PYPROJECT.value}', 'w') as out_file:
        i = 0
        while i < len(content):
            if content[i].startswith(MangagedPoetrySections.META):
                output.append(MangagedPoetrySections.META + '\n')
                [output.append(line + '\n') for line in plugin_sections.meta]
                output.append('\n')
                i += 1
            if content[i].startswith(MangagedPoetrySections.DEPS):
                i += get_section_output(i, content,
                                        output, global_sections.deps)
            if content[i].startswith(MangagedPoetrySections.DEV_DEPS):
                i += get_section_output(i, content,
                                        output, global_sections.dev_deps)
            if content[i].startswith(MangagedPoetrySections.INT_DEPS):
                i += get_section_output(i, content,
                                        output, global_sections.int_deps)
            if content[i].startswith(MangagedPoetrySections.RUFF):
                i += get_section_output(i, content,
                                        output, global_sections.ruff)
            if content[i].startswith(MangagedPoetrySections.RUFF_LINT):
                i += get_section_output(i, content,
                                        output, global_sections.ruff_lint)
            if content[i].startswith(MangagedPoetrySections.RUFF_FILES):
                i += get_section_output(i, content,
                                        output, global_sections.ruff_files)
            if content[i].startswith(MangagedPoetrySections.PYTEST):
                i += get_section_output(i, content,
                                        output, global_sections.pytest)
            if content[i].startswith(MangagedPoetrySections.COVERAGE):
                i += get_section_output(i, content,
                                        output, global_sections.coverage)
            if content[i].startswith(MangagedPoetrySections.COVERAGE_REPORT):
                i += get_section_output(i, content, output,
                                        global_sections.coverage_report)
            if content[i].startswith(MangagedPoetrySections.COVERAGE_XML):
                i += get_section_output(i, content,
                                        output, global_sections.coverage_xml)
            if content[i].startswith(MangagedPoetrySections.BUILD):
                i += get_section_output(i, content,
                                        output, global_sections.build)
            else:
                i += 1
        out_file.writelines(output)
    replace_plugin_tag(f'./{name}/{TAGGED_FILES.PYPROJECT.value}', PluginInfo(name))


def get_and_combine_integration_poetry_sections(name: str) -> (Sections, Sections):
    """Get the global integration sections and combine them with the plugin specific sections."""
    global_sections = Sections()
    plugin_sections = Sections()
    with open(f'./{GLOBAL_PLUGIN_DIR}/{TAGGED_FILES.PYPROJECT_INTEGRATION.value}', 'r') as file:
        filedata = file.read()
    extract_common_sections(filedata, global_sections)

    with open(f'./{name}/{TAGGED_FILES.PYPROJECT_INTEGRATION.value}', 'r') as file:
        filedata = file.read()

    extract_common_sections(filedata, plugin_sections)
    combine_dependenices(plugin_sections.deps, global_sections.deps)
    combine_dependenices(plugin_sections.dev_deps, global_sections.dev_deps)

    return global_sections, plugin_sections


def process_integration_config_sections(name: str, plugin_sections: Sections, global_sections: Sections) -> None:
    """Process the integration test config sections and write them to the plugins intergqtion/pyproject.toml file."""
    with open(f'./{GLOBAL_PLUGIN_DIR}/{TAGGED_FILES.PYPROJECT_INTEGRATION.value}', 'r') as in_file:
        content = in_file.readlines()

    output = []
    with open(f'./{name}/{TAGGED_FILES.PYPROJECT_INTEGRATION.value}', 'w') as out_file:
        i = 0
        while i < len(content):
            if content[i].startswith(MangagedPoetrySections.META):
                output.append(MangagedPoetrySections.META + '\n')
                i += 1
                [output.append(line + '\n') for line in plugin_sections.meta]
                output.append('\n')
            if content[i].startswith(MangagedPoetrySections.DEPS):
                i += get_section_output(i, content,
                                        output, global_sections.deps)
            if content[i].startswith(MangagedPoetrySections.DEV_DEPS):
                i += get_section_output(i, content,
                                        output, global_sections.dev_deps)
            if content[i].startswith(MangagedPoetrySections.BUILD):
                i += get_section_output(i, content,
                                        output, global_sections.build)
            else:
                i += 1
        out_file.writelines(output)


def replace_global_sections(name: str) -> None:
    """
    Combine the global sections with the plugin specific sections and write them to the plugins pyproject.toml file
    with the global dependencies overriding the plugin dependencies.
    """
    global_sections, plugin_sections = get_and_combine_main_poetry_sections(name)
    process_main_config_sections(name, plugin_sections, global_sections)
    global_sections, plugin_sections = get_and_combine_integration_poetry_sections(
        name)
    process_integration_config_sections(name, plugin_sections, global_sections)


def is_plugin_directory(plugin_name: str) -> bool:
    # If there is a drirectory which is not a plugin it should be ignored here
    return os.path.isdir(plugin_name) and plugin_name != GLOBAL_PLUGIN_DIR and not plugin_name.startswith('.')


def main():
    print("Checking poetry is available...")
    response = os.system('which poetry')
    if response == "":
        print("Poetry is not available. Please install poetry.")
        exit(1)

    options = """
        What would you like to do? 
        (1) Create a new plugin
        (2) Update all plugin common poetry sections 
        (3) Update all plugin common development files 
        (4) Exit \n\nInput:  """
    selection = input(options)

    # Create a new plugin
    if selection == "1":
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

    # Update common poetry sections
    elif selection == "2":
        msg = """Updating all plugin common poetry sections: This will take the global sections from the plugin_globals and combine them with the plugin specific sections, and install and update the lock file \n"""
        print(msg)
        for plugin_name in os.listdir('./'):
            if is_plugin_directory(plugin_name):
                print(f'Updating common poetry sections in {plugin_name}\n')
                replace_global_sections(plugin_name)
                os.system(
                    f'cd {plugin_name} && rm poetry.lock && poetry install')
                os.system(
                    f'cd {plugin_name}/integration && rm poetry.lock && poetry install')
    # Update common development files
    elif selection == "3":
        msg = """Updating all plugin common development files: This will take the common development files from the plugin_globals and copy them into each plugin."""
        print(msg)
        for plugin_name in os.listdir('./'):
            if is_plugin_directory(plugin_name):
                print(f'Updating development files in {plugin_name}\n')
                copy_and_tag_shared_files(info=PluginInfo(
                    name=plugin_name), new_plugin=False)

if __name__ == "__main__":
    main()