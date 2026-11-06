"""The data every parser produces and every analysis consumes."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import NamedTuple

PYPI = "PyPI"
NPM = "npm"
CRATES = "crates.io"
GO = "Go"
ECOSYSTEMS = (PYPI, NPM, CRATES, GO)


class Pkg(NamedTuple):
    """One locked package: an exact version in an OSV ecosystem."""

    ecosystem: str
    name: str
    version: str

    def label(self) -> str:
        return f"{self.name} {self.version}"


@dataclass
class Lockfile:
    """A parsed lockfile: the packages, which of them the project asked for
    directly, and the dependency edges between them."""

    path: str
    kind: str  # uv.lock, poetry.lock, ...
    ecosystem: str
    packages: set[Pkg] = field(default_factory=set)
    direct: set[Pkg] = field(default_factory=set)
    edges: dict[Pkg, set[Pkg]] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    @property
    def transitive(self) -> set[Pkg]:
        return self.packages - self.direct

    def add_edge(self, src: Pkg, dst: Pkg) -> None:
        if src != dst:
            self.edges.setdefault(src, set()).add(dst)
