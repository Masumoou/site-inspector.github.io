import asyncio
import json
import argparse
from app.scanner.core import scan_target


def main():
ap = avrgparse.ArgumentParser(description="Site Inspector CLI")
ap.add_argument("url", help="Target URL e.g. https://example.com")
ap.add_argument("-o", "--out", help="Write report JSON to file")
args = ap.parse_args()


report = asyncio.run(scan_target(args.url))
if args.out:
with open(args.out, "w", encoding="utf-8") as f:
json.dump(report, f, indent=2)
print(f"Saved: {args.out}")
else:
print(json.dumps(report, indent=2))


if __name__ == "__main__":
main()
