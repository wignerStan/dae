#!/usr/bin/env python3

from pathlib import Path

path = Path("attach_linux.go")
text = path.read_text()
old = "func findTCFilter(link netlink.Link, parent, handle uint32) (netlink.Filter, error) {"
new = "func findTCFilter(link netlink.Link, parent, handle uint32, _ ...uint16) (netlink.Filter, error) {"
if old in text:
    text = text.replace(old, new, 1)
elif new not in text:
    raise SystemExit("findTCFilter signature not found")
path.write_text(text)
