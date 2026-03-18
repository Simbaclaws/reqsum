from __future__ import annotations
import argparse
from pathlib import Path
from .parser import parse_file
from .pypi import Cache, fetch_summary, fetch_metadata
from .annotate import format_annotated, format_categorized


def cmd_summarize(argv=None):
    ap = argparse.ArgumentParser(prog="reqsum summarize", description="Annotate requirements.txt with PyPI summaries")
    ap.add_argument("input", help="Path to requirements.txt")
    ap.add_argument("-o", "--output", help="Write to file instead of stdout")
    ap.add_argument("--cache", default=".reqsum_cache.json", help="Path to cache file (JSON)")
    ap.add_argument("--no-align", action="store_true", help="Do not align inline comments")
    ap.add_argument("--categorize", action="store_true", help="Include category information")
    ap.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout (seconds)")
    args = ap.parse_args(argv)

    lines = list(parse_file(args.input))
    cache = Cache(Path(args.cache))

    names = [ln.name for ln in lines if ln.kind == "requirement" and ln.name]
    summaries = {}
    metadata_map = {}
    
    for name in names:
        if name in summaries:
            continue
        if args.categorize:
            metadata = fetch_metadata(name, cache, timeout=args.timeout)
            if metadata:
                summaries[name] = metadata.summary
                metadata_map[name] = metadata
            else:
                # Create fallback metadata using just the package name
                from .pypi import derive_category, PackageMetadata
                fallback_category = derive_category([], name, "", "")
                fallback_metadata = PackageMetadata(
                    summary=f"No metadata available - categorized by name as: {fallback_category}",
                    category=fallback_category,
                    keywords="",
                    classifiers=[]
                )
                summaries[name] = fallback_metadata.summary
                metadata_map[name] = fallback_metadata
        else:
            s = fetch_summary(name, cache, timeout=args.timeout)
            if s:
                summaries[name] = s
    cache.save()

    if args.categorize:
        text = format_categorized(lines, metadata_map, align=not args.no_align)
    else:
        text = format_annotated(lines, summaries, align=not args.no_align)

    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        import sys
        if sys.platform == "win32":
            # Windows console handling
            try:
                print(text, end="")
            except UnicodeEncodeError:
                # Write to stdout as bytes
                sys.stdout.buffer.write(text.encode('utf-8', errors='replace'))
        else:
            print(text, end="")


def main():
    ap = argparse.ArgumentParser(prog="reqsum", description="Summarize requirements.txt (no AI)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("summarize", help="Annotate requirements").set_defaults(func=cmd_summarize)
    args, rest = ap.parse_known_args()
    return args.func(rest)

if __name__ == "__main__":
    main()