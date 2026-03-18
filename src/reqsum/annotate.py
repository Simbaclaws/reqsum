
from __future__ import annotations
from typing import Iterable, Dict
from collections import defaultdict
from .parser import Line
from .pypi import PackageMetadata

def format_annotated(lines: Iterable[Line], summaries: dict[str, str], align: bool = True) -> str:
    # determine padding width only over requirement-like lines
    req_lines = [ln for ln in lines if ln.kind in {"requirement", "vcs", "url", "path", "editable", "include", "constraint", "option"} and ln.value]
    pad = max((len(ln.value) for ln in req_lines), default=0) + 2

    out = []
    for ln in lines:
        if ln.kind in {"blank", "comment"}:
            out.append(ln.raw.rstrip("\n"))
            continue
        value = ln.value
        suffix = ln.comment or ""

        if ln.kind == "requirement" and ln.name:
            summary = summaries.get(ln.name)
            if summary:
                if align:
                    out.append(f"{value.ljust(pad)}# {summary}")
                else:
                    out.append(f"{value}  # {summary}")
                continue
        # non-PyPI or missing summary
        hint = None
        if ln.kind == "vcs":
            hint = "VCS requirement"
        elif ln.kind == "url":
            hint = "URL requirement"
        elif ln.kind == "path":
            hint = "Local path requirement"
        elif ln.kind == "editable":
            hint = "Editable requirement"
        elif ln.kind == "include":
            hint = "Include another requirements file"
        elif ln.kind == "constraint":
            hint = "Constraints file"
        elif ln.kind == "option":
            hint = "Pip option"

        if hint:
            if align:
                out.append(f"{value.ljust(pad)}# {hint}")
            else:
                out.append(f"{value}  # {hint}")
        else:
            out.append(value)
    return "\n".join(out) + "\n"

def get_dynamic_category_order(categories: Dict[str, list]) -> list:
    """Dynamically determine category order based on actual content and common patterns"""
    
    # Priority categories that commonly appear first
    priority_keywords = {
        'Framework': 0,
        'Development': 1, 
        'Software Development': 2,
        'Documentation': 3,
        'Internet': 4,
        'System': 5,
        'Database': 6,
        'Scientific/Engineering': 7,
        'Text Processing': 8,
        'Multimedia': 9,
        'Communications': 10,
        'Security': 11,
        'Testing': 12,
        'Utilities': 13
    }
    
    # Sort categories by priority, then by package count (descending), then alphabetically
    sorted_categories = sorted(
        categories.items(),
        key=lambda x: (
            priority_keywords.get(x[0].split(' :: ')[0], 99),
            -len(x[1]),  # More packages first
            x[0]  # Alphabetical as tie-breaker
        )
    )
    
    return [cat for cat, _ in sorted_categories]

def format_categorized(lines: Iterable[Line], metadata_map: Dict[str, PackageMetadata], align: bool = True) -> str:
    # Group packages by category
    categories = defaultdict(list)
    non_packages = []
    
    for ln in lines:
        if ln.kind == "requirement" and ln.name and ln.name in metadata_map:
            metadata = metadata_map[ln.name]
            categories[metadata.category].append((ln, metadata))
        elif ln.kind in {"blank", "comment"}:
            non_packages.append(ln)
        else:
            non_packages.append(ln)
    
    out = []
    
    # Get dynamic category order
    category_order = get_dynamic_category_order(categories)
    
    # Add categories in dynamic order
    for cat in category_order:
        items = categories[cat]
        out.append(f"\n# {cat} ({len(items)} packages)")
        out.append("#" + "-" * (len(cat) + 10))
        for ln, metadata in items:
            comment = f"{metadata.summary}"
            if metadata.keywords:
                comment += f" | Keywords: {metadata.keywords}"
            if align:
                out.append(f"{ln.value.ljust(80)}# {comment}")
            else:
                out.append(f"{ln.value}  # {comment}")
    
    # Add non-package lines at the end
    if non_packages:
        out.append("\n# Other requirements")
        out.append("#" + "-" * 20)
        for ln in non_packages:
            if ln.kind in {"blank", "comment"}:
                out.append(ln.raw.rstrip("\n"))
            else:
                hint = None
                if ln.kind == "vcs":
                    hint = "VCS requirement"
                elif ln.kind == "url":
                    hint = "URL requirement"
                elif ln.kind == "path":
                    hint = "Local path requirement"
                elif ln.kind == "editable":
                    hint = "Editable requirement"
                elif ln.kind == "include":
                    hint = "Include another requirements file"
                elif ln.kind == "constraint":
                    hint = "Constraints file"
                elif ln.kind == "option":
                    hint = "Pip option"
                
                if hint:
                    if align:
                        out.append(f"{ln.value.ljust(80)}# {hint}")
                    else:
                        out.append(f"{ln.value}  # {hint}")
                else:
                    out.append(ln.value)
    
    return "\n".join(out) + "\n"
