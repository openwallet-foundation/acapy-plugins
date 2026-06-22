import json
import os
import re
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from copy import deepcopy
from enum import Enum
from pathlib import Path
from typing import Optional, Tuple

GLOBAL_PLUGIN_DIR = "plugin_globals"


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


class ManagedPoetrySections(str, Enum):
    META = "[tool.poetry]"
    DEPS = "[tool.poetry.dependencies]"
    DEV_DEPS = "[tool.poetry.group.dev.dependencies]"
    INT_DEPS = "[tool.poetry.group.integration.dependencies]"
    RUFF = "[tool.ruff]"
    RUFF_LINT = "[tool.ruff.lint]"
    RUFF_FILES = "[tool.ruff.lint.per-file-ignores]"
    PYTEST = "[tool.pytest.ini_options]"
    COVERAGE = "[tool.coverage.run]"
    COVERAGE_REPORT = "[tool.coverage.report]"
    COVERAGE_XML = "[tool.coverage.xml]"
    BUILD = "[build-system]"
    EXTRAS = "[tool.poetry.extras]"


sections = {
    "META": [],
    "DEPS": [],
    "DEV_DEPS": [],
    "INT_DEPS": [],
    "RUFF": [],
    "RUFF_LINT": [],
    "RUFF_FILES": [],
    "PYTEST": [],
    "COVERAGE": [],
    "COVERAGE_REPORT": [],
    "COVERAGE_XML": [],
    "BUILD": [],
    "EXTRAS": [],
}


class NEW_PLUGIN_FOLDERS(Enum):
    DOCKER = "docker"
    INTEGRATION = "integration"
    DEVCONTAINER = ".devcontainer"
    VSCODE = ".vscode"


class NEW_PLUGIN_FILES(Enum):
    PYPROJECT = "pyproject.toml"
    README = "README.md"
    DEFINITION = "definition.py"


class TAGGED_FILES(Enum):
    DOCKER_DEFAULT = "docker/default.yml"
    DOCKERFILE = "docker/Dockerfile"
    DOCKER_INTEGRATION = "docker/integration.yml"
    PYPROJECT = "pyproject.toml"
    PYPROJECT_INTEGRATION = "integration/pyproject.toml"
    DEVCONTAINER = ".devcontainer/devcontainer.json"
    VSCODE = ".vscode/launch.json"


def replace_plugin_tag(path: str, info: PluginInfo):
    with open(path, "r") as file:
        filedata = file.read()
    filedata = filedata.replace(GLOBAL_PLUGIN_DIR, info.name)
    with open(path, "w") as file:
        file.write(filedata)


def copy_all_common_files_for_new_plugin(info: PluginInfo) -> None:
    for folder in list(NEW_PLUGIN_FOLDERS):
        shutil.copytree(
            f"./{GLOBAL_PLUGIN_DIR}/{folder.value}", f"./{info.name}/{folder.value}"
        )
    for file in list(NEW_PLUGIN_FILES):
        file_location = (
            f"./{info.name}/{file.value}"
            if not file == NEW_PLUGIN_FILES.DEFINITION
            else f"./{info.name}/{info.name}/{file.value}"
        )
        shutil.copyfile(f"./{GLOBAL_PLUGIN_DIR}/{file.value}", file_location)
    for file in list(TAGGED_FILES):
        replace_plugin_tag(f"./{info.name}/{file.value}", info)


def combine_dependencies(plugin_dependencies, global_dependencies) -> None:
    """Add the plugin dependencies to the global dependencies if they are plugin specific."""
    for p_dep in plugin_dependencies:
        if p_dep.split("=")[0].strip() not in [
            g_dep.split("=")[0].strip() for g_dep in global_dependencies
        ]:
            global_dependencies.append(p_dep)


def is_end_of_section(line: str, current_section: str) -> bool:
    str_line = line.strip()
    return (
        str_line in [section.value for section in ManagedPoetrySections]
        and str_line != current_section
    )


def get_section(i: int, filedata: list, arr: list, current_section: str) -> int:
    """Put the section into the array and return the number of lines in the section."""
    j = i
    while j < len(filedata) and not is_end_of_section(filedata[j], current_section):
        arr.append(filedata[j])
        j += 1
    # Remove the last empty line
    if arr[-1] == "":
        arr.pop()
    return j - i


def extract_common_sections(filedata: str, sections: dict) -> None:
    """Go through the file by line and extract the section into the sections object."""
    filedata = filedata.split("\n")
    for i in range(len(filedata)):
        line = filedata[i]
        for section in ManagedPoetrySections:
            if line.startswith(section.value):
                i += get_section(i + 1, filedata, sections[section.name], section.value)


def get_section_output(
    i: int, content: list, output: list, section: list, current_section: str
) -> int:
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
    while j < len(content) - 1 and not is_end_of_section(content[j], current_section):
        j += 1
    while len(section) > 0:
        output.append(section.pop(0) + "\n")
    output.append("\n")
    return j - i


def get_and_combine_main_poetry_sections(name: str) -> Tuple[dict, dict]:
    """Get the global main sections and combine them with the plugin specific sections."""
    global_sections = deepcopy(sections)
    plugin_sections = deepcopy(sections)

    with open(f"./{GLOBAL_PLUGIN_DIR}/{TAGGED_FILES.PYPROJECT.value}", "r") as file:
        filedata = file.read()
        extract_common_sections(filedata, global_sections)

    with open(f"./{name}/{TAGGED_FILES.PYPROJECT.value}", "r") as file:
        filedata = file.read()
        extract_common_sections(filedata, plugin_sections)

    combine_dependencies(plugin_sections["DEPS"], global_sections["DEPS"])
    combine_dependencies(plugin_sections["EXTRAS"], global_sections["EXTRAS"])
    combine_dependencies(plugin_sections["DEV_DEPS"], global_sections["DEV_DEPS"])
    combine_dependencies(plugin_sections["INT_DEPS"], global_sections["INT_DEPS"])
    combine_dependencies(plugin_sections["PYTEST"], global_sections["PYTEST"])
    return global_sections, plugin_sections


def process_main_config_sections(
    name: str, plugin_sections: dict, global_sections: dict
) -> None:
    """Process the main config sections and write them to the plugins pyproject.toml file."""
    with open(f"./{GLOBAL_PLUGIN_DIR}/{TAGGED_FILES.PYPROJECT.value}", "r") as in_file:
        content = in_file.readlines()

    sections = [section.value for section in ManagedPoetrySections]

    output = []
    with open(f"./{name}/{TAGGED_FILES.PYPROJECT.value}", "w") as out_file:
        i = 0
        while i < len(content):
            if content[i].startswith(ManagedPoetrySections.META.value):
                output.append(ManagedPoetrySections.META.value + "\n")
                [output.append(line + "\n") for line in plugin_sections["META"]]
                output.append("\n")
                i += 1

            for section in sections:
                if content[i].startswith(section):
                    i += get_section_output(
                        i,
                        content,
                        output,
                        global_sections[ManagedPoetrySections(content[i].strip()).name],
                        content[i],
                    )
            else:
                i += 1
        out_file.writelines(output)
    replace_plugin_tag(f"./{name}/{TAGGED_FILES.PYPROJECT.value}", PluginInfo(name))


def get_and_combine_integration_poetry_sections(name: str) -> tuple[dict, dict]:
    """Get the global integration sections and combine them with the plugin specific sections."""
    global_sections = deepcopy(sections)
    plugin_sections = deepcopy(sections)
    with open(
        f"./{GLOBAL_PLUGIN_DIR}/{TAGGED_FILES.PYPROJECT_INTEGRATION.value}", "r"
    ) as file:
        filedata = file.read()
    extract_common_sections(filedata, global_sections)

    with open(f"./{name}/{TAGGED_FILES.PYPROJECT_INTEGRATION.value}", "r") as file:
        filedata = file.read()

    extract_common_sections(filedata, plugin_sections)
    combine_dependencies(plugin_sections["DEPS"], global_sections["DEPS"])
    combine_dependencies(plugin_sections["DEV_DEPS"], global_sections["DEV_DEPS"])
    combine_dependencies(plugin_sections["PYTEST"], global_sections["PYTEST"])

    return global_sections, plugin_sections


def process_integration_config_sections(
    name: str, plugin_sections: dict, global_sections: dict
) -> None:
    """Process the integration test config sections and write them to the plugins integration/pyproject.toml file."""
    with open(
        f"./{GLOBAL_PLUGIN_DIR}/{TAGGED_FILES.PYPROJECT_INTEGRATION.value}", "r"
    ) as in_file:
        content = in_file.readlines()

    sections = [section.value for section in ManagedPoetrySections]

    output = []
    with open(f"./{name}/{TAGGED_FILES.PYPROJECT_INTEGRATION.value}", "w") as out_file:
        i = 0
        while i < len(content):
            if content[i].startswith(ManagedPoetrySections.META.value):
                output.append(ManagedPoetrySections.META.value + "\n")
                [output.append(line + "\n") for line in plugin_sections["META"]]
                i += 1
                output.append("\n")

            for section in sections:
                if content[i].startswith(section):
                    i += get_section_output(
                        i,
                        content,
                        output,
                        global_sections[ManagedPoetrySections(content[i].strip()).name],
                        content[i],
                    )
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
    if is_plugin_directory(name, True):
        global_sections, plugin_sections = get_and_combine_integration_poetry_sections(
            name
        )
        process_integration_config_sections(name, plugin_sections, global_sections)


def is_plugin_directory(plugin_name: str, exclude_lite_plugins: bool = False) -> bool:
    # If there is a directory which is not a plugin it should be ignored here
    if exclude_lite_plugins:
        lite_plugins = Path("lite_plugins").read_text().splitlines()
        return (
            os.path.isdir(plugin_name)
            and plugin_name != GLOBAL_PLUGIN_DIR
            and not plugin_name.startswith(".")
            and plugin_name not in lite_plugins
        )
    return (
        os.path.isdir(plugin_name)
        and plugin_name != GLOBAL_PLUGIN_DIR
        and not plugin_name.startswith(".")
    )


def update_all_poetry_locks():
    dirs = []
    for root, _, files in os.walk("."):
        if "poetry.lock" in files:
            dirs.append(root)

    def run_lock(root):
        print(f"Updating poetry.lock in {root}")
        subprocess.run(["poetry", "lock"], cwd=root)

    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = {executor.submit(run_lock, d): d for d in dirs}
        for future in as_completed(futures):
            future.result()


def _run_poetry_update(names: list):
    """Update poetry.lock for every directory that contains any of the named packages."""
    dirs = []
    for root, _, files in os.walk("."):
        if "poetry.lock" in files:
            with open(f"{root}/poetry.lock", "r") as file:
                content = file.read()
            if any(f'name = "{v}"' in content for name in names for v in (name, name.replace("-", "_"))):
                dirs.append(root)

    if not dirs:
        print("No poetry.lock files found containing the specified packages.")
        return

    def run_update(root):
        print(f"Updating poetry.lock in {root}")
        subprocess.run(["poetry", "update", "--lock", *names], cwd=root)

    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = {executor.submit(run_update, d): d for d in dirs}
        for future in as_completed(futures):
            future.result()


def upgrade_library_in_all_plugins(arg: str = None):
    from ls_dep_libs import extract_libraries, get_open_dependabot_prs

    if arg is not None and not arg.startswith("--"):
        print(
            "\nOption (7) has changed and no longer accepts library names directly.\n\n"
            "Usage:\n"
            "  python repo_manager.py 7           List libraries with open Dependabot PRs\n"
            "  python repo_manager.py 7 --debug   Same, with PR number and title detail\n"
            "  python repo_manager.py 7 --apply   Upgrade all those libraries across all plugins\n"
        )
        return

    prs = get_open_dependabot_prs()
    if not prs:
        print("No open Dependabot PRs found.")
        return

    all_libraries: set[str] = set()
    pr_libs = []
    for pr in prs:
        libs = sorted(set(extract_libraries(pr["title"], pr["body"])))
        all_libraries.update(libs)
        pr_libs.append((pr, libs))

    if arg == "--debug":
        print(f"{'PR':>6}  {'Library/Libraries':<35}  Title")
        print("-" * 110)
        for pr, libs in pr_libs:
            lib_str = ", ".join(libs) if libs else "(unknown)"
            print(f"#{pr['number']:>5}  {lib_str:<35}  {pr['title']}")
        return

    if arg is None:
        for lib in sorted(all_libraries):
            print(lib)
        return

    # --apply
    if not all_libraries:
        print("No libraries to update.")
        return
    names = sorted(all_libraries)
    print(f"Upgrading libraries across all plugins: {', '.join(names)}\n")
    _run_poetry_update(names)


def close_pr_range(start: int, end: int):
    for i in range(start, end + 1):
        os.system(f"gh pr close {i}")


def find_dependabot_toml_updates(apply: bool = False):
    """Find open Dependabot PRs that modify pyproject.toml, extract the version changes,
    and list any local pyproject.toml files that still carry the old version.
    Pass apply=True to update the exact-match files and regenerate their lock files."""
    result = subprocess.run(
        [
            "gh", "pr", "list",
            "--author", "app/dependabot",
            "--state", "open",
            "--limit", "200",
            "--json", "number,title",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    prs = json.loads(result.stdout)

    if not prs:
        print("No open Dependabot PRs found.")
        return

    # (pkg, old_ver, new_ver) -> sorted list of PR numbers
    all_changes: dict[tuple, list] = {}

    for pr in prs:
        diff_result = subprocess.run(
            ["gh", "pr", "diff", str(pr["number"])],
            capture_output=True,
            text=True,
        )
        diff = diff_result.stdout

        if "pyproject.toml" not in diff:
            continue

        # Split into per-file sections on the "diff --git" boundary
        file_sections = re.split(r"^diff --git ", diff, flags=re.MULTILINE)

        for section in file_sections:
            first_line = section.split("\n", 1)[0]
            if "pyproject.toml" not in first_line:
                continue

            removed: dict[str, str] = {}
            added: dict[str, str] = {}

            for line in section.split("\n"):
                # Skip the unified-diff file header lines
                if line.startswith("---") or line.startswith("+++"):
                    continue
                m = re.match(r'^-([\w][\w.-]*)\s*=\s*"([^"]+)"', line)
                if m:
                    removed[m.group(1)] = m.group(2)
                m = re.match(r'^\+([\w][\w.-]*)\s*=\s*"([^"]+)"', line)
                if m:
                    added[m.group(1)] = m.group(2)

            for pkg, old_ver in removed.items():
                new_ver = added.get(pkg)
                if new_ver and new_ver != old_ver:
                    key = (pkg, old_ver, new_ver)
                    if pr["number"] not in all_changes.get(key, []):
                        all_changes.setdefault(key, []).append(pr["number"])

    if not all_changes:
        print("No open Dependabot PRs found that update pyproject.toml files.")
        return

    print("Dependabot PRs with pyproject.toml version changes:\n")

    # (path, pkg, old_ver, new_ver) — only exact-old-version matches, for --apply
    exact_matches: list[tuple[str, str, str, str]] = []

    for (pkg, old_ver, new_ver), pr_nums in sorted(all_changes.items()):
        pr_list = ", ".join(f"#{n}" for n in sorted(pr_nums))
        print(f"  {pkg}: \"{old_ver}\" -> \"{new_ver}\"  [{pr_list}]")

        any_ver_pattern = re.compile(
            rf'^{re.escape(pkg)}\s*=\s*"([^"]+)"',
            re.MULTILINE,
        )
        old_ver_files = []
        other_ver_files = []
        for root, dirs, files in os.walk("."):
            # Skip virtual-environment trees
            dirs[:] = [d for d in dirs if d not in (".venv", "venv", "__pycache__")]
            if "pyproject.toml" in files:
                path = os.path.join(root, "pyproject.toml")
                with open(path) as f:
                    content = f.read()
                m = any_ver_pattern.search(content)
                if not m:
                    continue
                found_ver = m.group(1)
                if found_ver == old_ver:
                    old_ver_files.append(path)
                    exact_matches.append((path, pkg, old_ver, new_ver))
                elif found_ver != new_ver:
                    other_ver_files.append((path, found_ver))

        if old_ver_files:
            print(f"    Needs update (has old version \"{old_ver}\"):")
            for path in sorted(old_ver_files):
                print(f"      {path}")
        if other_ver_files:
            print(f"    Has a different version (also needs review):")
            for path, ver in sorted(other_ver_files):
                print(f"      {path}  (\"{ver}\")")
        if not old_ver_files and not other_ver_files:
            print("    (no local pyproject.toml files reference this package with an outdated version)")
        print()

    if not apply:
        return

    if not exact_matches:
        print("Nothing to apply (no exact old-version matches found).")
        return

    print("The following pyproject.toml files will be updated:")
    for path, pkg, old_ver, new_ver in sorted(exact_matches):
        print(f"  {path}  ({pkg}: \"{old_ver}\" -> \"{new_ver}\")")

    confirm = input("\nAre you sure? (y/N): ").strip().lower()
    if confirm != "y":
        print("Aborted.")
        return

    # Apply the version string replacements
    for path, pkg, old_ver, new_ver in exact_matches:
        content = Path(path).read_text()
        new_content = re.sub(
            rf'^({re.escape(pkg)}\s*=\s*"){re.escape(old_ver)}"',
            rf'\g<1>{new_ver}"',
            content,
            flags=re.MULTILINE,
        )
        Path(path).write_text(new_content)
        print(f"Updated {path}")

    # Regenerate lock files — group packages by directory so one poetry call handles
    # multiple package updates in the same directory.
    pkgs_by_dir: dict[str, set] = {}
    for path, pkg, _, _ in exact_matches:
        d = os.path.dirname(path) or "."
        pkgs_by_dir.setdefault(d, set()).add(pkg)

    def update_lock(dir_path: str, pkgs: set):
        print(f"Updating poetry.lock in {dir_path} ...")
        subprocess.run(["poetry", "update", "--lock", *sorted(pkgs)], cwd=dir_path)

    print("\nRegenerating poetry.lock files...")
    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = {executor.submit(update_lock, d, pkgs): d for d, pkgs in pkgs_by_dir.items()}
        for future in as_completed(futures):
            future.result()


def main(arg_1=None, arg_2=None, arg_3=None):
    options = """
        What would you like to do? 
        (1) Create a new plugin
        (2) Update all plugin common poetry sections 
        (3) Upgrade plugin_global dependencies 
        (4) Update plugins description with supported acapy-agent version
        (5) Get the plugins that upgraded since last release
        (6) Update all poetry.lock files
        (7) List/upgrade libraries from open Dependabot PRs (--debug for detail, --apply to upgrade)
        (8) Close a range of PRs
        (9) Find Dependabot PRs with pyproject.toml updates and affected local files
        (10) Exit \n\nInput:  """

    if arg_1:
        selection = arg_1
    else:
        selection = input(options)

    if selection != "4" and selection != "5":
        print("Checking poetry is available...")
        response = os.system("which poetry")
        if response == "":
            print("Poetry is not available. Please install poetry.")
            exit(1)

    if selection == "1":
        # Create a new plugin
        msg = """Creating a new plugin: This will create a blank plugin with all the common files and folders needed to get started developing and testing."""
        print(msg)
        name = input("Enter the plugin name (recommended to use snake_case): ")
        if name == "":
            print("You must enter a plugin name")
            exit(1)
        version = str(input("Enter the plugin version (default is 0.1.0): ") or "0.1.0")
        description = input("Enter the plugin description (default is ''): ") or ""

        plugin_info = PluginInfo(name, version, description)
        os.makedirs(f"./{name}/{name}/v1_0")
        copy_all_common_files_for_new_plugin(plugin_info)

        os.system(f"cd {name} && poetry install --all-extras")

    elif selection == "2":
        # Update common poetry sections
        msg = """Updating all plugin common poetry sections: This will take the global sections from the plugin_globals and combine them with the plugin specific sections, and install and update the lock file \n"""
        print(msg)
        for plugin_name in os.listdir("./"):
            if is_plugin_directory(plugin_name):
                print(f"Updating common poetry sections in {plugin_name}\n")
                replace_global_sections(plugin_name)
                os.system(f"cd {plugin_name} && poetry lock --no-update")
                # Don't update lite plugin integration files (They don't have any)
                if is_plugin_directory(plugin_name, True):
                    os.system(
                        f"cd {plugin_name}/integration && poetry lock --no-update"
                    )

    elif selection == "3":
        # Upgrade plugin globals lock file
        msg = """Upgrade plugin_global dependencies \n"""
        print(msg)
        os.system("cd plugin_globals && poetry lock")

    # Update plugins description with supported acapy-agent version
    elif selection == "4":
        """
        1. Update the description of each plugin with the supported acapy-agent version.
        2. Output text for the release notes in markdown form.
        """

        # Get the acapy-agent version from the global poetry.lock file
        with open("./plugin_globals/poetry.lock", "r") as file:
            for line in file:
                if 'name = "acapy-agent"' in line:
                    next_line = next(file, None)
                    global_version = re.findall(r'"([^"]*)"', next_line)
                    break
        # Create and output the markdown release notes
        msg = f"""## ACA-Py Release {global_version[0]}\n"""
        print(msg)
        # Markdown table header
        print("| Plugin Name | Supported ACA-Py Release |")
        print("| --- | --- |")
        for plugin_name in sorted(os.listdir("./")):
            if is_plugin_directory(plugin_name):
                # Plugin specific acapy-agent version
                with open(f"./{plugin_name}/poetry.lock", "r") as file:
                    for line in file:
                        if 'name = "acapy-agent"' in line:
                            next_line = next(file, None)
                            version = re.findall(r'"([^"]*)"', next_line)
                            break
                # Extract the description from the pyproject.toml file
                with open(f"./{plugin_name}/pyproject.toml", "r") as file:
                    filedata = file.read()
                    linedata = filedata.split("\n")
                    for i in range(len(linedata)):
                        line = linedata[i]
                        if "description = " in line:
                            description = re.findall(r'"([^"]*)"', line)
                            description_line = line
                            break

                # Replace the description with the supported acapy-agent version at the end
                if description[0].find("Supported acapy-agent version") != -1:
                    description[0] = description[0].split(
                        " (Supported acapy-agent version"
                    )[0]

                filedata = filedata.replace(
                    description_line,
                    f'description = "{description[0]} (Supported acapy-agent version: {version[0]}) "',
                )

                with open(f"./{plugin_name}/pyproject.toml", "w") as file:
                    file.write(filedata)
                print(f"|{plugin_name} | {version[0]}|")

        print("\n")

    elif selection == "5":
        """
        Extract the plugins from the RELEASES.md and determine which plugins which can be
        upgraded or are new based off of the global acapy-agent version.
        """

        # All the plugins. Used to determine which plugins are new.
        all_plugins = [
            plugin for plugin in os.listdir("./") if is_plugin_directory(plugin)
        ]

        # Get the acapy-agent version from the global poetry.lock file
        with open("./plugin_globals/poetry.lock", "r") as file:
            for line in file:
                if 'name = "acapy-agent"' in line:
                    next_line = next(file, None)
                    global_version = re.findall(r'"([^"]*)"', next_line)
                    break

        # Extract the plugins and versions from the last release in the RELEASES.md file
        with open("RELEASES.md", "r") as file:
            last_releases = []
            for line in file:
                if f"## ACA-Py Release {global_version[0]}" in line:
                    line = next(file)
                    line = next(file)
                    line = next(file)
                    while "### Plugins Upgraded" not in line:
                        if (
                            line != "| Plugin Name | Supported ACA-Py Release |\n"
                            and line != "| --- | --- |\n"
                        ):
                            last_releases.append(line.strip())
                        line = next(file)
                    break

        # All plugins that have been released on the last release. Used to determine which plugins can be upgraded.
        plugins_on_old_release = []
        # All plugins that have been released. Used to determine which plugins are new.
        released_plugins = []

        # Get all released plugins and the plugins not on the global version
        for item in last_releases:
            split_item = item.split("|")
            if len(split_item) > 1:
                released_plugins.append(split_item[1].strip())

                if split_item[2].strip() == global_version[0]:
                    plugins_on_old_release.append(split_item[1].strip())

        # If there is releases in the RELEASES.md file then look for new plugins and add them to plugins on old release
        if last_releases:
            new_plugins = [
                plugin for plugin in all_plugins if plugin not in released_plugins
            ]
            for plugin in new_plugins:
                plugins_on_old_release.append(plugin)
        output = ""
        for plugin in plugins_on_old_release:
            output += f"{plugin} "

        print(output)
    elif selection == "6":
        print("Updating all poetry.lock files in nested directories...")
        update_all_poetry_locks()
    elif selection == "7":
        upgrade_library_in_all_plugins(arg_2)
    elif selection == "8":
        print(f"Closing a range prs from {arg_2} to {arg_3}...")
        close_pr_range(int(arg_2), int(arg_3))
    elif selection == "9":
        find_dependabot_toml_updates(apply=arg_2 == "--apply")
    elif selection == "10":
        print("Exiting...")
        exit(0)
    else:
        print("Invalid selection. Please try again.")
        main()


if __name__ == "__main__":
    try:
        main(
            sys.argv[1] if len(sys.argv) > 1 else None,
            " ".join(sys.argv[2:]) if len(sys.argv) > 2 else None,
            sys.argv[3] if len(sys.argv) > 3 else None,
        )
    except Exception:
        main()
