#! /bin/bash

MKDOCS=mkdocs.yml

# Clean up when not testing the docs
if [ "$1" == "clean" ]; then
  rm ${MKDOCS}
  rm -rf docs/f
  exit 0
fi

# Generate everything that is needed for publishing the docs
mkdir -p docs
cp *.md docs
cp LICENSE docs/LICENSE.md

# Generate the main part of the mkdocs.yml file
cat <<-EOF >${MKDOCS}
site_name: ACA-Py Plugins
repo_name: openwallet-foundation/acapy-plugins
repo_url: https://github.com/openwallet-foundation/acapy-plugins
theme:
  name: material
  logo: https://raw.githubusercontent.com/hyperledger/aries-acapy-docs/main/assets/Hyperledger_Aries_Logo_White.png
  favicon: https://raw.githubusercontent.com/hyperledger/aries-cloudagent-python/main/docs/assets/aries-favicon.png
  icon:
    repo: fontawesome/brands/github
  palette:
    # Palette toggle for light mode
    - media: "(prefers-color-scheme: light)"
      scheme: default
      toggle:
        icon: material/brightness-7
        name: Switch to dark mode
    # Palette toggle for dark mode
    - media: "(prefers-color-scheme: dark)"
      scheme: slate
      toggle:
        icon: material/brightness-4
        name: Switch to light mode
  features:
  - content.code.copy
  - navigation.expand
  - navigation.footer
  - navigation.instant
  - navigation.tabs
  - navigation.tabs.sticky
  - navigation.top
  - navigation.tracking
  - toc.follow
#  - toc.integrate
markdown_extensions:
  - abbr
  - admonition
  - attr_list
  - def_list
  - footnotes
  - md_in_html
  - toc:
      permalink: true
      toc_depth: 3
  - pymdownx.arithmatex:
      generic: true
  - pymdownx.betterem:
      smart_enable: all
  - pymdownx.caret
  - pymdownx.details
  - pymdownx.emoji:
      emoji_generator: !!python/name:material.extensions.emoji.to_svg
      emoji_index: !!python/name:material.extensions.emoji.twemoji
  - pymdownx.highlight:
      anchor_linenums: true
  - pymdownx.inlinehilite
  - pymdownx.keys
  - pymdownx.magiclink:
      repo_url_shorthand: true
      user: squidfunk
      repo: mkdocs-material
  - pymdownx.mark
  - pymdownx.smartsymbols
  - pymdownx.superfences:
      custom_fences:
        - name: mermaid
          class: mermaid
          format: !!python/name:pymdownx.superfences.fence_code_format
  - pymdownx.tabbed:
      alternate_style: true
  - pymdownx.tasklist:
      custom_checkbox: true
  - pymdownx.tilde
plugins:
  - search
  - mike
extra:
  version:
    provider: mike
nav:
- Welcome!:
    - ACA-Py Plugins: README.md
    - Plugin Release Status: RELEASES.md
- Plugins:
EOF

# Generate the per-plugin navigation entries
for d in */ ; do
  if [ ${d}  != "docs/" ] && [ -f ${d}README.md ] && [ ${d}  != "plugin_globals/" ]; then
    echo "   - " $(head -1 ${d}README.md | sed "s/^[# ]*//") ":" ${d}README.md >>${MKDOCS}
    mkdir -p docs/${d}
    cp ${d}README.md docs/${d}
  fi
done

# Generate the remaining navigation entries
cat <<-EOF >>${MKDOCS}
- Archived: archived_plugins.md
- Contributing:
    - How to Contribute: CONTRIBUTING.md
    - Maintainers: MAINTAINERS.md
    - Managing the Plugin Docs Site: DOCSITE.md
    - License: LICENSE.md
EOF
