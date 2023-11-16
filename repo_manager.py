import os
from re import M
import shutil

from bases import get


class PluginInfo:
    def __init__(
        self,
        name: str,
        version: str,
        description: str,
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
    RUFF_FILES = '[tool.ruff.lint.ignore]'
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
        self.extra = []


def replace_plugin_tag(path: str, info: PluginInfo):
    with open(path, 'r') as file:
        filedata = file.read()
    print(filedata)
    filedata = filedata.replace('plugin_globals', info.name)
    with open(path, 'w') as file:
        file.write(filedata)


def is_blank_line(line: str) -> bool:
    return len(line.strip()) == 0


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
    replace_plugin_tag(f'./{info.name}/integration/pyproject.toml', info)
    replace_plugin_tag(f'./{info.name}/pyproject.toml', info)


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


def combine_dependenices(plugin_dependencies, global_dependencies):
    for p_dep in plugin_dependencies:
        if (p_dep.split('=')[0].strip() not in [g_dep.split('=')[0].strip() for g_dep in global_dependencies]):
            global_dependencies.append(p_dep)
    global_dependencies.sort()


def get_section(i: int, filedata: list, arr: list) -> int:
    j = i
    while j < len(filedata) - 1 and not is_blank_line(filedata[j]):
        arr.append(filedata[j])
        j += 1
    return j - i


def extract_common_sections(filedata: str, sections: Sections):
    filedata = filedata.split('\n')
    for i in range(len(filedata)):
        line = filedata[i]
        if line == MangagedPoetrySections.META:
            i += get_section(i + 1, filedata, sections.meta)
        elif line == MangagedPoetrySections.DEPS:
            i += get_section(i + 1, filedata, sections.deps)
        elif line == MangagedPoetrySections.DEV_DEPS:
            i += get_section(i + 1, filedata, sections.dev_deps)
        elif line == MangagedPoetrySections.INT_DEPS:
            i += get_section(i + 1, filedata, sections.int_deps)
        elif line == MangagedPoetrySections.RUFF:
            i += get_section(i + 1, filedata, sections.ruff)
        elif line == MangagedPoetrySections.RUFF_LINT:
            i += get_section(i + 1, filedata, sections.ruff_lint)
        elif line == MangagedPoetrySections.RUFF_FILES:
            i += get_section(i + 1, filedata, sections.ruff_files)
        elif line == MangagedPoetrySections.PYTEST:
            i += get_section(i + 1, filedata, sections.pytest)
        elif line == MangagedPoetrySections.COVERAGE:
            i += get_section(i + 1, filedata, sections.coverage)
        elif line == MangagedPoetrySections.COVERAGE_REPORT:
            i += get_section(i + 1, filedata, sections.coverage_report)
        elif line == MangagedPoetrySections.COVERAGE_XML:
            i += get_section(i + 1, filedata, sections.coverage_xml)
        elif line == MangagedPoetrySections.BUILD:
            i += get_section(i + 1, filedata, sections.build)
        else:
            sections.extra.append(line)


def get_section_output(i: int, content: list, output: list, section: list) -> int:
    j = i
    output.append(content[j])
    while (j < len(content) - 1 and not is_blank_line(content[j])):
        j += 1
    while (len(section) > 0):
        output.append(section.pop(0) + '\n')
    output.append('\n')
    return j - i


def replace_global_sections(name: str):
    global_sections = Sections()
    plugin_sections = Sections()

    # Parent pyproject.toml
    with open('./plugin_globals/pyproject.toml', 'r') as file:
        filedata = file.read()
        extract_common_sections(filedata, global_sections)

    with open(f'./{name}/pyproject.toml', 'r') as file:
        filedata = file.read()
        extract_common_sections(filedata, plugin_sections)
        combine_dependenices(plugin_sections.deps, global_sections.deps)
        combine_dependenices(plugin_sections.dev_deps,
                             global_sections.dev_deps)
        combine_dependenices(plugin_sections.int_deps,
                             global_sections.int_deps)

    with open('./plugin_globals/pyproject.toml', 'r') as in_file:
        content = in_file.readlines()

    output = []
    with open(f'./{name}/pyproject.toml', 'w') as out_file:
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

    # Integration pyproject.toml
    global_sections = Sections()
    plugin_sections = Sections()
    with open('./plugin_globals/integration/pyproject.toml', 'r') as file:
        filedata = file.read()
    extract_common_sections(filedata, global_sections)

    with open(f'./{name}/integration/pyproject.toml', 'r') as file:
        filedata = file.read()

    extract_common_sections(filedata, plugin_sections)
    combine_dependenices(plugin_sections.deps, global_sections.deps)
    combine_dependenices(plugin_sections.dev_deps, global_sections.dev_deps)

    with open('./plugin_globals/integration/pyproject.toml', 'r') as in_file:
        content = in_file.readlines()

    output = []
    with open(f'./{name}/integration/pyproject.toml', 'w') as out_file:
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
    (2) Update all plugin common poetry sections 
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
    msg = """Updating all plugin common poetry sections: This will take the global sections from the plugin_globals and combine them with the plugin specific sections, and install and update the lock file \n"""
    print(msg)
    for plugin_name in os.listdir('./'):
        if is_plugin_dir(plugin_name):
            print(f'Updating {plugin_name}\n')
            replace_global_sections(plugin_name)
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
