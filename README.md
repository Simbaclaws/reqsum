# reqsum

A small, deterministic CLI to **annotate a `requirements.txt` file with one-line summaries** for each package, **without using AI**. It fetches summaries from the **PyPI JSON API** and writes an annotated file.

## Features
- Reads a `requirements.txt` (supports `-r`, `-c`, VCS/URL, editable `-e`, markers, extras)
- Fetches `info.summary` for PyPI-hosted packages
- Caches responses locally (JSON file) to avoid repeated network calls
- Outputs to stdout or a file; preserves original requirement lines
- Optional alignment of inline comments

## Install (editable)
```bash
python -m pip install -e .
```

## Usage
```bash
# annotate in-place to a new file
reqsum summarize requirements.txt -o requirements_annotated.txt

# print to stdout
reqsum summarize requirements.txt

# control comment alignment and cache file
reqsum summarize requirements.txt --no-align --cache .reqsum_cache.json
```

## How it works
- Parses requirement lines using `packaging.requirements.Requirement` where applicable.
- For a package name `foo`, queries `https://pypi.org/pypi/foo/json` and uses `info.summary`.
- Lines that aren't PyPI-normal packages (e.g. local paths, VCS) are copied with an explanatory comment.

## Notes
- This tool does **not** use AI and relies on the package summaries provided by authors on PyPI.
- Network access is required the first time a package is seen (then cached).
- Some categorizations are still hardcoded...

## License
GPLv3
