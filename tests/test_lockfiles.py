import json
import os

import pytest

from depaudit_mcp import lockfiles as lf
from depaudit_mcp.errors import LockfileError
from depaudit_mcp.model import NPM, PYPI, Pkg

NPM_DIRECT = {"lodash 4.17.15", "mkdirp 0.5.1", "@babel/core 7.0.0"}


def names(pkgs):
    return {p.label() for p in pkgs}


def test_uv_lock(fix):
    lk = lf.parse(os.path.join(fix("uv"), "uv.lock"))
    assert lk.ecosystem == PYPI
    assert Pkg(PYPI, "requests", "2.19.1") in lk.direct
    assert Pkg(PYPI, "urllib3", "1.23") in lk.transitive
    assert Pkg(PYPI, "urllib3", "1.23") in lk.edges[Pkg(PYPI, "requests", "2.19.1")]
    # the dev group's pytest is direct; both python-version-specific pins appear
    assert {"pytest 8.4.2", "pytest 9.2.0"} <= names(lk.direct)
    assert not any(p.name == "demo" for p in lk.packages)  # the project itself is not audited


def test_poetry_lock(fix):
    lk = lf.parse(os.path.join(fix("poetry"), "poetry.lock"))
    assert names(lk.direct) == {"requests 2.19.1", "pytest 7.4.4"}
    assert Pkg(PYPI, "urllib3", "1.23") in lk.edges[Pkg(PYPI, "requests", "2.19.1")]
    assert Pkg(PYPI, "idna", "2.7") in lk.transitive


def test_poetry_without_pyproject_says_so(tmp_path, fix):
    with open(os.path.join(fix("poetry"), "poetry.lock"), "rb") as fh:
        (tmp_path / "poetry.lock").write_bytes(fh.read())
    lk = lf.parse(str(tmp_path / "poetry.lock"))
    assert "requests 2.19.1" in names(lk.direct)
    assert any("no pyproject.toml" in n for n in lk.notes)


def test_requirements(fix):
    lk = lf.parse(os.path.join(fix("requirements"), "requirements.txt"))
    assert names(lk.packages) == {"requests 2.19.1", "pyyaml 5.3", "jinja2 2.10"}  # names normalised
    assert lk.direct == lk.packages and not lk.edges
    joined = " | ".join(lk.notes)
    assert "flask" in joined and "numpy" in joined and "-r other.txt" in joined


def test_package_lock(fix):
    lk = lf.parse(os.path.join(fix("npm"), "package-lock.json"))
    assert names(lk.direct) == NPM_DIRECT
    assert Pkg(NPM, "minimist", "0.0.8") in lk.edges[Pkg(NPM, "mkdirp", "0.5.1")]
    assert len(lk.packages) == 35


@pytest.mark.parametrize("project", ["pnpm9", "pnpm6"])
def test_pnpm_lock_matches_npm(fix, project):
    """Same package.json -> pnpm v6 and v9 lockfiles must agree with npm on what is direct and
    on the mkdirp -> minimist edge."""
    lk = lf.parse(os.path.join(fix(project), "pnpm-lock.yaml"))
    assert names(lk.direct) == NPM_DIRECT
    assert Pkg(NPM, "minimist", "0.0.8") in lk.edges[Pkg(NPM, "mkdirp", "0.5.1")]
    assert Pkg(NPM, "json5", "0.5.1") in lk.edges[Pkg(NPM, "@babel/core", "7.0.0")]
    npm = lf.parse(os.path.join(fix("npm"), "package-lock.json"))
    assert {p.name for p in lk.packages} == {p.name for p in npm.packages}


def test_yarn_lock(fix):
    lk = lf.parse(os.path.join(fix("yarn"), "yarn.lock"))
    assert names(lk.direct) == NPM_DIRECT
    assert Pkg(NPM, "minimist", "0.0.8") in lk.edges[Pkg(NPM, "mkdirp", "0.5.1")]


def test_cargo_lock(fix):
    lk = lf.parse(os.path.join(fix("cargo"), "Cargo.lock"))
    assert names(lk.direct) == {"chrono 0.4.19", "smallvec 0.6.9", "num-traits 0.2.19"}
    assert "time 0.1.43" in names(lk.transitive)
    # workspace members and git sources are not audited
    assert not any(p.name in ("demo", "gitdep", "local-helper") for p in lk.packages)


def test_go_sum(fix):
    lk = lf.parse(os.path.join(fix("go"), "go.sum"))
    # /go.mod-only lines are ignored
    assert names(lk.packages) == {"github.com/gin-gonic/gin v1.6.3", "golang.org/x/text v0.3.0"}
    assert names(lk.direct) == {"github.com/gin-gonic/gin v1.6.3"}  # go.mod marks x/text indirect


def test_npm_nested_resolution_and_workspaces(tmp_path):
    lock = {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"a": "1"}, "workspaces": ["packages/*"]},
            "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "2", "c": "1"}},
            "node_modules/b": {"version": "1.0.0"},
            "node_modules/a/node_modules/b": {"version": "2.0.0"},
            "node_modules/c": {"version": "1.5.0", "dependencies": {"b": "1"}},
            "node_modules/ws": {"resolved": "packages/ws", "link": True},
            "packages/ws": {"name": "ws", "version": "0.1.0", "dependencies": {"c": "1"}},
            "node_modules/alias": {"name": "real-name", "version": "3.0.0"},
        },
    }
    p = tmp_path / "package-lock.json"
    p.write_text(json.dumps(lock), encoding="utf-8")
    lk = lf.parse(str(p))
    a, b1, b2, c = (Pkg(NPM, "a", "1.0.0"), Pkg(NPM, "b", "1.0.0"), Pkg(NPM, "b", "2.0.0"), Pkg(NPM, "c", "1.5.0"))
    assert lk.edges[a] == {b2, c}  # nested node_modules/b wins over the hoisted one for a
    assert lk.edges[c] == {b1}  # c has no nested b, so it sees the hoisted one
    assert a in lk.direct and c in lk.direct  # root dep and workspace member dep
    assert Pkg(NPM, "real-name", "3.0.0") in lk.packages  # aliased installs use the real name


def test_yaml_subset():
    doc = lf.parse_yaml_map(
        "a: '1.0'\n"
        "m:\n"
        "  'x@1(y@2)':\n"
        "    resolution: {integrity: sha512-abc, tarball: https://x}\n"
        "    dependencies:\n"
        "      y: 2.0.0\n"
        "    os:\n"
        "      - darwin\n"
        "      - linux\n"
        "  empty: {}\n"
    )
    assert doc["a"] == "1.0"
    entry = doc["m"]["x@1(y@2)"]
    assert entry["dependencies"] == {"y": "2.0.0"}
    assert entry["os"] == ["darwin", "linux"]
    assert entry["resolution"].startswith("{integrity")
    assert doc["m"]["empty"] == "{}"


def test_detect_walks_directories_but_skips_node_modules(tmp_path):
    (tmp_path / "uv.lock").write_text("", encoding="utf-8")
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "package-lock.json").write_text("{}", encoding="utf-8")
    (tmp_path / "web" / "node_modules" / "x").mkdir(parents=True)
    (tmp_path / "web" / "node_modules" / "x" / "package-lock.json").write_text("{}", encoding="utf-8")
    (tmp_path / "requirements-dev.txt").write_text("", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("", encoding="utf-8")
    found = sorted(os.path.relpath(p, tmp_path).replace("\\", "/") for p in lf.detect(str(tmp_path)))
    assert found == ["requirements-dev.txt", "uv.lock", "web/package-lock.json"]


@pytest.mark.parametrize(
    "filename,content,message",
    [
        ("package-lock.json", '{"lockfileVersion": 1, "dependencies": {}}', "lockfileVersion 1"),
        ("pnpm-lock.yaml", "lockfileVersion: 5.4\n", "older than 6.0"),
        ("yarn.lock", "__metadata:\n  version: 6\n", "Yarn Berry"),
        ("uv.lock", "this is = not [valid toml", "does not look like a valid uv.lock"),
        ("package-lock.json", "{nope", "does not look like a valid package-lock.json"),
        ("Cargo.lock", "[[package]]\nname = 'x'\nsource = 'registry+x'\n", "does not look like a valid Cargo.lock"),
    ],
)
def test_clear_errors_for_unsupported_or_broken_lockfiles(tmp_path, filename, content, message):
    (tmp_path / filename).write_text(content, encoding="utf-8")
    with pytest.raises(LockfileError, match=message):
        lf.parse(str(tmp_path / filename))


def test_detect_errors(tmp_path):
    with pytest.raises(LockfileError, match="no lockfile found"):
        lf.detect(str(tmp_path))
    with pytest.raises(LockfileError, match="does not exist"):
        lf.detect(str(tmp_path / "nope"))
    (tmp_path / "x.txt").write_text("", encoding="utf-8")
    with pytest.raises(LockfileError, match="not a supported lockfile"):
        lf.detect(str(tmp_path / "x.txt"))
