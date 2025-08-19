#!/usr/bin/env python3
import subprocess, json, re

REPOS = [
    "https://gitlab.com/gitlab-org/gitlab.git",         # EE
    "https://gitlab.com/gitlab-org/gitlab-foss.git",    # CE
]

# Разрешаем X.Y(.Z) + rc/pre в разных форматах + -ee/.DBee
VER_RE = re.compile(
    r"^v?("                       # опциональная 'v'
    r"\d+\.\d+(?:\.\d+)?"         # 12.3 или 12.3.4
    r"(?:[.-]rc\d+|[.-]rc\d{6,}|[.-]pre\d*|[.-]pre)?"  # rc/pre
    r"(?:-ee|\.DBee)?"            # -ee или .DBee
    r")$"
)

def ls_tags(url: str):
    out = subprocess.check_output(["git", "ls-remote", "--tags", url], text=True)
    return out.splitlines()

# tag_name -> {"commit": <sha> or "tagobj": <sha>}
tags = {}
for url in REPOS:
    for line in ls_tags(url):
        sha, ref = line.split()
        tag = ref.rsplit("/", 1)[-1]
        deref = tag.endswith("^{}")
        if deref:
            tag = tag[:-3]
        # фильтруем только "версионные" теги
        if not VER_RE.match(tag):
            continue
        entry = tags.setdefault(tag, {})
        if deref:
            entry["commit"] = sha
        else:
            entry.setdefault("tagobj", sha)

# Финальная мапа: SHA коммита -> версия (без ведущей 'v')
result = {}
for tag, data in tags.items():
    sha = data.get("commit") or data.get("tagobj")
    version = tag.lstrip("v")
    result[sha[:12]] = version        # хотите полный SHA — уберите [:12]

with open("revs.json", "w") as f:
    json.dump(result, f, indent=2, sort_keys=True)

print(f"Saved {len(result)} revisions.")
