#!/usr/bin/env python3
"""
dockergen - stack-aware, security-hardened Dockerfile / docker-compose generator.

Scans a directory tree (a monorepo of services, or a single service repo), detects
language / framework / versions / port / health endpoint / backing services, and writes:

  <service>/Dockerfile          multi-stage, non-root, minimal runtime image
  <service>/.dockerignore       keeps secrets and junk out of the build context
  <service>/nginx.conf          (React/Vue/Angular SPAs only) hardened nginx config
  docker-compose.yml            (--compose) apps + only the infra they actually use
  .env.example, infra/*         (--compose) required variables and DB init scripts
  dockergen-report.json         what was detected, per service

Supported: Java (Spring Boot, Quarkus, plain; Maven/Gradle), Python (Django, FastAPI,
Flask; pip/poetry/uv/pipenv), .NET (ASP.NET Core 6+), Go, Node (React/Vue/Angular SPA,
Next.js, Express/Nest/Fastify).

Generated files carry a "Managed-By: dockergen" marker. Hand-written Dockerfiles are
never touched unless --force is given. Per-service overrides: <service>/.dockergen.json

Stdlib only, Python 3.9+.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set

__version__ = "1.0.0"
MARKER = "# Managed-By: dockergen"
UID = 10001  # numeric non-root uid (numeric so K8s runAsNonRoot can verify it)

# Single place to bump base images. Prefer pointing --base-registry at your internal
# mirror and --digests at a digest map maintained by Renovate/Dependabot.
IMAGES = {
    "temurin_jre": "eclipse-temurin:{v}-jre-alpine",
    "temurin_jdk": "eclipse-temurin:{v}-jdk",
    "maven": "maven:3.9-eclipse-temurin-{v}",
    "gradle8": "gradle:8-jdk{v}",
    "gradle9": "gradle:9-jdk{v}",
    "python": "python:{v}-slim",
    "golang": "golang:{v}-alpine",
    "distroless_static": "gcr.io/distroless/static-debian12:nonroot",
    "dotnet_sdk": "mcr.microsoft.com/dotnet/sdk:{v}",
    "dotnet_aspnet_chiseled": "mcr.microsoft.com/dotnet/aspnet:{v}-noble-chiseled",
    "dotnet_aspnet": "mcr.microsoft.com/dotnet/aspnet:{v}",
    "dotnet_runtime_chiseled": "mcr.microsoft.com/dotnet/runtime:{v}-noble-chiseled",
    "dotnet_runtime": "mcr.microsoft.com/dotnet/runtime:{v}",
    "node": "node:{v}-alpine",
    "nginx": "nginxinc/nginx-unprivileged:1.28-alpine",
}

SKIP_DIRS = {
    "node_modules", "target", "build", "dist", "venv", ".venv", "env", "__pycache__", "vendor",
    "bin", "obj", "out", "site-packages", "coverage", "test", "tests", "__tests__", "e2e",
}

INFRA_SIGNALS = {
    "postgres": r"postgres|psycopg|asyncpg|npgsql|lib/pq|jackc/pgx|\"pg\"\s*:|pg-promise",
    "mysql": r"mysql|mariadb|pymysql|mysqlclient|pomelo",
    "redis": r"redis|lettuce|jedis|ioredis",
    "memcached": r"memcache|pylibmc|enyim|spymemcached",
    "kafka": r"kafka|sarama|franz-go",
    "mongodb": r"mongo",
    "rabbitmq": r"rabbit|amqp",
}


# --------------------------------------------------------------------------- helpers
def read(p: Path, limit: int = 400_000) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="ignore")[:limit]
    except OSError:
        return ""


def walk(d: Path, max_depth: int = 4) -> Iterator[Path]:
    base = len(d.parts)
    for root, dirs, files in os.walk(d):
        dirs[:] = sorted(x for x in dirs if x not in SKIP_DIRS and not x.startswith("."))
        if len(Path(root).parts) - base >= max_depth:
            dirs[:] = []
        for f in sorted(files):
            yield Path(root) / f


def sanitize(s: str) -> str:
    return re.sub(r"[^a-z0-9-]+", "-", s.lower()).strip("-") or "app"


def jq(items: List[str]) -> str:
    return json.dumps(items)


def run(cmds: List[str], mounts: List[str] = ()) -> str:
    head = "RUN "
    if mounts:
        head += " \\\n    ".join(mounts) + " \\\n    "
    return head + " \\\n && ".join(cmds)


def first_int(pattern: str, text: str, flags: int = re.M) -> Optional[int]:
    m = re.search(pattern, text, flags)
    return int(m.group(1)) if m else None


@dataclass
class Service:
    name: str
    path: Path
    rel: str
    language: str = ""
    framework: str = ""
    version: str = ""
    port: int = 8080
    health_path: Optional[str] = None
    infra: Set[str] = field(default_factory=set)
    notes: List[str] = field(default_factory=list)
    data: Dict = field(default_factory=dict)
    cfg: Dict = field(default_factory=dict)
    files: Dict[str, str] = field(default_factory=dict)  # extra files to write


@dataclass
class Ctx:
    registry: str = ""
    digests: Dict[str, str] = field(default_factory=dict)
    vendor: str = ""

    def img(self, key: str, **fmt) -> str:
        ref = IMAGES[key].format(**fmt)
        if self.digests.get(ref):
            ref = f"{ref}@{self.digests[ref]}"
        if self.registry and not ref.startswith("scratch"):
            ref = f"{self.registry.rstrip('/')}/{ref}"
        return ref


# --------------------------------------------------------------------------- detection helpers
HEALTH_RE = re.compile(r"""["'](/(?:actuator/health|healthz|health|livez|readyz|ping))["']""")


def find_health(d: Path, exts: Set[str]) -> Optional[str]:
    n = 0
    for f in walk(d, 5):
        if f.suffix in exts:
            n += 1
            if n > 400:
                break
            m = HEALTH_RE.search(read(f, 200_000))
            if m:
                return m.group(1)
    return None


def detect_infra(d: Path) -> Set[str]:
    manifests = {"pom.xml", "build.gradle", "build.gradle.kts", "requirements.txt", "pyproject.toml",
                 "Pipfile", "go.mod", "package.json", "Pipfile.lock"}
    blob = []
    n = 0
    for f in walk(d, 5):
        nm = f.name
        if (nm in manifests or nm.endswith(".csproj") or re.match(r"requirements.*\.txt$", nm)
                or re.match(r"application.*\.(properties|ya?ml)$", nm)
                or re.match(r"appsettings.*\.json$", nm) or nm.startswith(".env") or nm in ("settings.py", "docker-compose.yml")):
            blob.append(read(f, 150_000).lower())
            n += 1
            if n > 80:
                break
    text = "\n".join(blob)
    return {k for k, pat in INFRA_SIGNALS.items() if re.search(pat, text)}


def lts_java(v: int) -> int:
    for lts in (8, 11, 17, 21, 25):
        if v <= lts:
            return lts
    return 25


# --------------------------------------------------------------------------- analyzers
def analyze_java(s: Service, d: Path) -> None:
    maven = (d / "pom.xml").exists()
    if maven:
        build_files = [p for p in walk(d, 3) if p.name == "pom.xml"]
    else:
        build_files = [p for p in walk(d, 3) if p.name in ("build.gradle", "build.gradle.kts")]
    texts = {p: read(p) for p in build_files}
    alltext = "\n".join(texts.values())
    root_text = texts.get(d / ("pom.xml" if maven else "build.gradle"), "") or next(iter(texts.values()), "")

    module = None
    if maven and "<modules>" in root_text:
        apps = [p for p, t in texts.items() if p.parent != d and re.search(r"spring-boot-maven-plugin|quarkus-maven-plugin", t)]
        if apps:
            module = str(apps[0].parent.relative_to(d))
            if len(apps) > 1:
                s.notes.append(f"Multi-module build with {len(apps)} runnable modules; picked '{module}'. Override in .dockergen.json.")
        else:
            s.notes.append("Multi-module Maven project but no runnable module found; building the whole reactor.")

    s.framework = "springboot" if "spring-boot" in alltext else "quarkus" if "quarkus" in alltext else "java"
    ver = None
    for pat in (r"<java\.version>\s*(\d+(?:\.\d+)?)", r"<maven\.compiler\.release>\s*(\d+)", r"<release>\s*(\d+)",
                r"<maven\.compiler\.(?:source|target)>\s*(\d+(?:\.\d+)?)", r"JavaLanguageVersion\.of\((\d+)\)",
                r"(?:source|target)Compatibility\s*=?\s*['\"]?(?:JavaVersion\.VERSION_)?(\d+(?:[._]\d+)?)",
                r"jvmTarget\s*=?\s*['\"](\d+(?:\.\d+)?)"):
        m = re.search(pat, alltext)
        if m:
            raw = m.group(1).replace("_", ".")
            ver = int(raw.split(".")[1]) if raw.startswith("1.") else int(raw.split(".")[0])
            break
    boot = first_int(r"spring-boot-starter-parent</artifactId>\s*<version>\s*(\d+)\.", alltext, re.S) or \
        first_int(r"org\.springframework\.boot['\"]?\)?\s*version\s*['\"](\d+)\.", alltext)
    if boot and boot >= 3:
        ver = max(ver or 0, 17)
    s.version = str(lts_java(ver)) if ver else "21"
    if not ver:
        s.notes.append("Java version not declared; defaulting to 21 (LTS).")

    gradle_kind = (d / "gradlew").exists()
    s.data = {"maven": maven, "module": module, "wrapper": (d / ("mvnw" if maven else "gradlew")).exists(),
              "boot": s.framework == "springboot", "quarkus": s.framework == "quarkus",
              "gradle_kind": gradle_kind}

    port = None
    for f in walk(d, 6):
        if re.match(r"application(-\w+)?\.(properties|ya?ml)$", f.name) and "src" in f.parts:
            t = read(f)
            port = first_int(r"^server\.port\s*[=:]\s*(?:\$\{[^:}]+:)?(\d{2,5})", t)
            if not port:
                m = re.search(r"^server:\s*\n((?:[ \t]+.*\n?)+)", t, re.M)
                if m:
                    port = first_int(r"^[ \t]+port:\s*(?:\$\{[^:}]+:)?(\d{2,5})", m.group(1))
            if port:
                break
    s.port = port or 8080
    if s.framework == "springboot" and "spring-boot-starter-actuator" in alltext:
        s.health_path = "/actuator/health"
    elif s.framework == "quarkus" and "smallrye-health" in alltext:
        s.health_path = "/q/health"
    else:
        s.health_path = find_health(d, {".java", ".kt"})
    if s.framework == "springboot" and not s.health_path:
        s.notes.append("spring-boot-starter-actuator not found: add it (health probes) - using TCP HEALTHCHECK.")


PY_MIN, PY_DEFAULT = (3, 11), "3.12"


def analyze_python(s: Service, d: Path) -> None:
    req = d / "requirements.txt"
    pyproj = read(d / "pyproject.toml")
    deps = (read(req) + "\n" + pyproj + "\n" + read(d / "Pipfile") + "\n" + read(d / "setup.py")).lower()
    for f in d.glob("requirements*.txt"):
        deps += "\n" + read(f).lower()

    if (d / "poetry.lock").exists():
        mgr = "poetry"
    elif (d / "uv.lock").exists():
        mgr = "uv"
    elif (d / "Pipfile.lock").exists():
        mgr = "pipenv"
    elif req.exists():
        mgr = "pip"
    elif (d / "pyproject.toml").exists() or (d / "setup.py").exists():
        mgr = "pyproject"
    else:
        mgr = "pip"
    s.data["mgr"] = mgr

    ver = None
    for f in (".python-version", "runtime.txt"):
        m = re.search(r"(\d+\.\d+)", read(d / f))
        if m:
            ver = m.group(1)
            break
    if not ver:
        m = re.search(r"python_version\s*=\s*[\"'](\d+\.\d+)", read(d / "Pipfile")) or \
            re.search(r"requires-python\s*=\s*[\"'][^\d]*(\d+\.\d+)", pyproj) or \
            re.search(r"^python\s*=\s*[\"'][^\d]*(\d+\.\d+)", pyproj, re.M)
        ver = m.group(1) if m else None
    if ver:
        t = tuple(int(x) for x in ver.split("."))
        if t < PY_MIN:
            s.notes.append(f"Python {ver} is end-of-life; using {PY_MIN[0]}.{PY_MIN[1]}. Test before shipping.")
            ver = f"{PY_MIN[0]}.{PY_MIN[1]}"
    s.version = ver or PY_DEFAULT

    pyfiles = [f for f in walk(d, 4) if f.suffix == ".py"][:300]
    fw = "django" if re.search(r"\bdjango\b", deps) or (d / "manage.py").exists() else \
        "fastapi" if "fastapi" in deps else "flask" if "flask" in deps else "python"
    s.framework = fw
    s.port = 8000
    s.data["gunicorn"] = "gunicorn" in deps
    s.data["uvicorn"] = "uvicorn" in deps
    s.data["build_pkgs"], s.data["runtime_pkgs"] = [], []
    if re.search(r"psycopg2(?!-binary)", deps):
        s.data["build_pkgs"].append("libpq-dev"); s.data["runtime_pkgs"].append("libpq5")
    if "mysqlclient" in deps:
        s.data["build_pkgs"].append("default-libmysqlclient-dev"); s.data["runtime_pkgs"].append("libmariadb3")
    if "pylibmc" in deps:
        s.data["build_pkgs"].append("libmemcached-dev"); s.data["runtime_pkgs"].append("libmemcached11")

    def modpath(f: Path) -> str:
        return ".".join(f.relative_to(d).with_suffix("").parts)

    cmd = None
    if fw == "django":
        wsgi = next((f for f in pyfiles if f.name == "wsgi.py"), None)
        asgi = next((f for f in pyfiles if f.name == "asgi.py"), None)
        if wsgi:
            cmd = ["gunicorn", "--bind", f"0.0.0.0:{s.port}", "--access-logfile", "-", f"{modpath(wsgi)}:application"]
            s.data["server"] = "gunicorn"
        elif asgi:
            cmd = ["uvicorn", f"{modpath(asgi)}:application", "--host", "0.0.0.0", "--port", str(s.port), "--proxy-headers"]
            s.data["server"] = "uvicorn"
        sets = [f for f in pyfiles if f.name.startswith("settings")]
        s.data["collectstatic"] = (d / "manage.py").exists() and any("STATIC_ROOT" in read(f) for f in sets)
    elif fw == "fastapi":
        for f in pyfiles:
            m = re.search(r"^(\w+)\s*(?::[^=\n]+)?=\s*FastAPI\(", read(f), re.M)
            if m:
                cmd = ["uvicorn", f"{modpath(f)}:{m.group(1)}", "--host", "0.0.0.0", "--port", str(s.port),
                       "--proxy-headers", "--no-server-header"]
                s.data["server"] = "uvicorn"
                break
    elif fw == "flask":
        for f in pyfiles:
            m = re.search(r"^(\w+)\s*=\s*Flask\(", read(f), re.M)
            if m:
                cmd = ["gunicorn", "--bind", f"0.0.0.0:{s.port}", "--access-logfile", "-", f"{modpath(f)}:{m.group(1)}"]
                s.data["server"] = "gunicorn"
                break
    if not cmd:
        entry = next((n for n in ("main.py", "app.py", "run.py") if (d / n).exists()), None)
        cmd = ["python", entry] if entry else ["python", "-m", "app"]
        s.notes.append("Could not detect the ASGI/WSGI entrypoint; verify CMD.")
    s.data["cmd"] = cmd
    s.health_path = find_health(d, {".py"})


def analyze_go(s: Service, d: Path) -> None:
    gomod = read(d / "go.mod")
    m = re.search(r"^go\s+(\d+\.\d+)", gomod, re.M)
    s.version = m.group(1) if m else "1.23"
    mains = []
    for f in walk(d, 5):
        if f.suffix == ".go" and not f.name.endswith("_test.go"):
            t = read(f, 100_000)
            if re.search(r"^package main\b", t, re.M) and re.search(r"^func main\(", t, re.M):
                mains.append(f)
    pkg = "."
    if mains:
        cmds = [f for f in mains if "cmd" in f.relative_to(d).parts]
        pick = (cmds or mains)[0]
        rel = pick.parent.relative_to(d)
        pkg = "." if str(rel) == "." else f"./{rel.as_posix()}"
        if len(mains) > 1:
            s.notes.append(f"{len(mains)} main packages found; building '{pkg}'.")
    else:
        s.notes.append("No main package found; building '.'.")
    s.data = {"pkg": pkg, "vendor": (d / "vendor").is_dir()}
    port = None
    for f in mains[:5]:
        t = read(f)
        for pat in (r"Listen\w*\(\s*\"[^\"]*:(\d{2,5})\"", r"Addr:\s*\"[^\"]*:(\d{2,5})\"", r"(?:Getenv|getEnv|Getenv\w*)\([^)]*,\s*\"(\d{4,5})\""):
            port = first_int(pat, t)
            if port:
                break
        if port:
            break
    s.port = port or 8080
    s.framework = "go"
    s.health_path = find_health(d, {".go"})


def analyze_dotnet(s: Service, d: Path) -> None:
    csprojs = [p for p in walk(d, 5) if p.suffix == ".csproj"]
    web = [p for p in csprojs if "Microsoft.NET.Sdk.Web" in read(p)]
    pick = (web or csprojs or [None])[0]
    if pick is None:
        s.notes.append("Solution without csproj found."); pick = d / "App.csproj"
    if len(web) > 1:
        s.notes.append(f"{len(web)} web projects in this repo; building '{pick.name}'. Override in .dockergen.json.")
    t = read(pick)
    m = re.search(r"<TargetFramework>net(\d+\.\d+)", t)
    s.version = m.group(1) if m else "8.0"
    if float(s.version) < 8.0:
        s.notes.append(f".NET {s.version} is out of support and has no chiseled image; upgrade the target framework.")
    asm = re.search(r"<AssemblyName>([^<]+)", t)
    restore_files = []
    for p in walk(d, 5):
        if p.suffix in (".sln", ".slnx", ".csproj") or p.name.lower() in ("nuget.config", "directory.build.props",
                                                                       "directory.packages.props", "global.json"):
            restore_files.append(p.relative_to(d).as_posix())
    s.data = {"proj": pick.relative_to(d).as_posix(), "asm": asm.group(1) if asm else pick.stem,
              "web": bool(web), "restore": restore_files[:60]}
    s.framework = "aspnetcore" if web else "dotnet"
    port = None
    for f in walk(d, 5):
        if f.name in ("Program.cs", "appsettings.json"):
            port = first_int(r"UseUrls\(\s*\"https?://[^\"]*:(\d{2,5})\"", read(f))
            if port:
                break
    s.port = port or 8080
    s.health_path = find_health(d, {".cs"})


def analyze_node(s: Service, d: Path) -> None:
    try:
        pkg = json.loads(read(d / "package.json"))
    except json.JSONDecodeError:
        pkg = {}
        s.notes.append("package.json is not valid JSON.")
    deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
    scripts = pkg.get("scripts", {})
    ver = None
    for f in (".nvmrc", ".node-version"):
        m = re.search(r"(\d+)", read(d / f))
        if m:
            ver = m.group(1); break
    if not ver:
        m = re.search(r"(\d+)", str(pkg.get("engines", {}).get("node", "")))
        ver = m.group(1) if m else None
    if ver and int(ver) < 20:
        s.notes.append(f"Node {ver} is end-of-life; using 22."); ver = "22"
    s.version = ver or "22"

    if (d / "pnpm-lock.yaml").exists():
        mgr = "pnpm"
    elif (d / "yarn.lock").exists():
        mgr = "yarn-berry" if (d / ".yarnrc.yml").exists() else "yarn"
    elif (d / "package-lock.json").exists():
        mgr = "npm"
    else:
        mgr = "npm-nolock"; s.notes.append("No lockfile: builds are not reproducible. Commit one.")
    server_deps = {"express", "fastify", "koa", "@nestjs/core", "@hapi/hapi", "hapi", "restify"}
    build_cmd = scripts.get("build", "")
    if "next" in deps:
        kind = "next"
    elif server_deps & set(deps):
        kind = "server"
    elif ("react" in deps or "vue" in deps or "@angular/core" in deps or "svelte" in deps) and build_cmd:
        kind = "spa"
    elif scripts.get("start"):
        kind = "server"
    else:
        kind = "spa" if build_cmd else "server"
    out = "build" if "react-scripts" in deps else "dist"
    if kind == "spa" and "@angular/core" in deps:
        s.notes.append("Angular: output is dist/<project>/browser - verify the COPY path in the Dockerfile.")
    s.framework = {"next": "nextjs", "server": "nest" if "@nestjs/core" in deps else "node",
                   "spa": "react" if "react" in deps else "spa"}[kind]
    standalone = False
    if kind == "next":
        cfg = "".join(read(d / n) for n in ("next.config.js", "next.config.mjs", "next.config.ts"))
        standalone = "standalone" in cfg
        if not standalone:
            s.notes.append("Next.js: add output:'standalone' to next.config for a ~10x smaller image.")
    entry = None
    if kind == "server":
        if "@nestjs/core" in deps:
            entry = ["node", "dist/main.js"]
        elif pkg.get("main"):
            entry = ["node", pkg["main"]]
        else:
            m = re.match(r"node\s+(\S+)", scripts.get("start", ""))
            entry = ["node", m.group(1)] if m else ["npm", "start"]
            if not m:
                s.notes.append("Could not resolve a direct 'node <file>' entrypoint; falling back to 'npm start'.")
    s.data = {"mgr": mgr, "kind": kind, "out": out, "standalone": standalone, "entry": entry,
              "has_build": bool(build_cmd), "public": (d / "public").is_dir(),
              "lock": [n for n in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", ".yarnrc.yml", ".npmrc") if (d / n).exists()]}
    if kind == "spa":
        s.port = 8080
        s.health_path = "/healthz"
    else:
        port = None
        for f in walk(d, 4):
            if f.suffix in (".js", ".ts", ".mjs"):
                t = read(f, 100_000)
                port = first_int(r"listen\(\s*(\d{2,5})", t) or first_int(r"PORT\s*(?:\|\||\?\?)\s*['\"]?(\d{2,5})", t)
                if port:
                    break
        s.port = port or 3000
        s.health_path = find_health(d, {".js", ".ts", ".mjs"})


MARKERS = [
    ("java", lambda d: any((d / f).exists() for f in ("pom.xml", "build.gradle", "build.gradle.kts")), analyze_java),
    ("dotnet", lambda d: any(d.glob("*.csproj")) or any(d.glob("*.sln")) or any(d.glob("*.slnx")), analyze_dotnet),
    ("go", lambda d: (d / "go.mod").exists(), analyze_go),
    ("python", lambda d: any((d / f).exists() for f in ("requirements.txt", "pyproject.toml", "Pipfile", "setup.py", "manage.py")), analyze_python),
    ("node", lambda d: (d / "package.json").exists(), analyze_node),
]


def is_workspace_root(d: Path) -> bool:
    if not (d / "package.json").exists() or any(f(d) for k, f, _ in MARKERS if k != "node"):
        return False
    try:
        return "workspaces" in json.loads(read(d / "package.json"))
    except json.JSONDecodeError:
        return False


def discover(root: Path, depth: int) -> List[Service]:
    found: List[Service] = []
    base = len(root.parts)
    for cur, dirs, _ in os.walk(root):
        d = Path(cur)
        dirs[:] = sorted(x for x in dirs if x not in SKIP_DIRS and not x.startswith("."))
        hits = [(k, an) for k, test, an in MARKERS if test(d)]
        if hits and not is_workspace_root(d):
            lang, analyzer = hits[0]
            rel = d.relative_to(root).as_posix()
            name = sanitize(root.name if rel == "." else rel.replace("/", "-"))
            s = Service(name=name, path=d, rel=rel, language=lang)
            if len(hits) > 1:
                s.notes.append(f"Multiple stacks in one directory ({', '.join(k for k, _ in hits)}); using {lang}.")
            cfgp = d / ".dockergen.json"
            if cfgp.exists():
                try:
                    s.cfg = json.loads(read(cfgp))
                except json.JSONDecodeError:
                    s.notes.append(".dockergen.json is invalid JSON - ignored.")
            if not s.cfg.get("skip"):
                analyzer(s, d)
                s.infra = detect_infra(d)
                apply_overrides(s)
                found.append(s)
            dirs[:] = []
        elif len(d.parts) - base >= depth:
            dirs[:] = []
    return found


def apply_overrides(s: Service) -> None:
    c = s.cfg
    if "port" in c:
        s.port = int(c["port"])
    if "health_path" in c:
        s.health_path = c["health_path"]
    if "version" in c:
        s.version = str(c["version"])
    if "entrypoint" in c:
        s.data["entry_override"] = c["entrypoint"]


# --------------------------------------------------------------------------- Dockerfile pieces
def header(s: Service) -> List[str]:
    return ["# syntax=docker/dockerfile:1.7", MARKER + f" v{__version__} - do not edit; customise via .dockergen.json",
            f"# Service: {s.name} | stack: {s.language}/{s.framework} {s.version}", ""]


def labels(s: Service, ctx: Ctx) -> List[str]:
    out = ["ARG VCS_REF=unknown", "ARG VCS_URL=unknown", "ARG BUILD_DATE=unknown", "ARG VERSION=dev",
           f'LABEL org.opencontainers.image.title="{s.name}" \\',
           '      org.opencontainers.image.source="$VCS_URL" \\',
           '      org.opencontainers.image.revision="$VCS_REF" \\',
           '      org.opencontainers.image.created="$BUILD_DATE" \\',
           '      org.opencontainers.image.version="$VERSION"' + (' \\' if ctx.vendor else "")]
    if ctx.vendor:
        out.append(f'      org.opencontainers.image.vendor="{ctx.vendor}"')
    return out


def hc_http(port: int, path: str) -> str:
    return (f"HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \\\n"
            f"  CMD wget -qO /dev/null http://127.0.0.1:{port}{path} || exit 1")


def alpine_user() -> str:
    return (f"RUN addgroup -g {UID} -S app && adduser -u {UID} -S -G app -H -s /sbin/nologin app")


def debian_user() -> str:
    return (f"RUN groupadd --system --gid {UID} app && "
            f"useradd --system --uid {UID} --gid app --no-create-home --shell /usr/sbin/nologin app")


def gen_java(s: Service, ctx: Ctx) -> str:
    v, dd = s.version, s.data
    L = header(s)
    mvn_mounts = ["--mount=type=cache,target=/root/.m2/repository",
                  "--mount=type=secret,id=mvn_settings,target=/root/.m2/settings.xml,required=false"]
    gr_mounts = ["--mount=type=cache,target=/root/.gradle"]
    if dd["maven"]:
        if dd["wrapper"]:
            L.append(f"FROM {ctx.img('temurin_jdk', v=v)} AS build")
            tool = "sh ./mvnw"
        else:
            L.append(f"FROM {ctx.img('maven', v=v)} AS build")
            tool = "mvn"
        pl = f"-pl {dd['module']} -am " if dd["module"] else ""
        tdir = f"{dd['module']}/target" if dd["module"] else "target"
        L += ["WORKDIR /workspace", "COPY . ."]
        if dd["quarkus"]:
            L.append(run([f"{tool} -B -ntp -q -DskipTests {pl}package", f"mkdir -p /out && cp -r {tdir}/quarkus-app /out/app"], mvn_mounts))
        else:
            L.append(run([f"{tool} -B -ntp -q -DskipTests {pl}package", "mkdir -p /out",
                          f"cp \"$(find {tdir} -maxdepth 1 -name '*.jar' ! -name '*-plain.jar' ! -name '*-sources.jar' ! -name '*-javadoc.jar' ! -name 'original-*' | head -n1)\" /out/app.jar"], mvn_mounts))
    else:
        if dd["gradle_kind"]:
            L.append(f"FROM {ctx.img('temurin_jdk', v=v)} AS build")
            tool = "sh ./gradlew"
        else:
            L.append(f"FROM {ctx.img('gradle9' if int(v) >= 25 else 'gradle8', v=v)} AS build")
            tool = "gradle"
        task = "bootJar" if dd["boot"] else "build"
        L += ["WORKDIR /workspace", "COPY . ."]
        if dd["quarkus"]:
            L.append(run([f"{tool} --no-daemon -x test quarkusBuild", "mkdir -p /out && cp -r build/quarkus-app /out/app"], gr_mounts))
        else:
            L.append(run([f"{tool} --no-daemon -x test {task}", "mkdir -p /out",
                          "cp \"$(find . -path '*/build/libs/*.jar' ! -name '*-plain.jar' ! -name '*-sources.jar' ! -name '*-javadoc.jar' | head -n1)\" /out/app.jar"], gr_mounts))
    L += ["", f"FROM {ctx.img('temurin_jre', v=v)} AS runtime", alpine_user(), "WORKDIR /app"]
    if dd["quarkus"]:
        L.append(f"COPY --from=build --chown={UID}:{UID} /out/app/ /app/")
        entry = ["java", "-jar", "/app/quarkus-run.jar"]
    else:
        L.append(f"COPY --from=build --chown={UID}:{UID} /out/app.jar /app/app.jar")
        entry = ["java", "-jar", "/app/app.jar"]
    entry = s.data.get("entry_override", entry)
    L += ['# Container-aware JVM defaults; override with JAVA_TOOL_OPTIONS at deploy time.',
          'ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=75.0 -XX:+ExitOnOutOfMemoryError -Djava.security.egd=file:/dev/./urandom"',
          f"EXPOSE {s.port}", f"USER {UID}:{UID}"]
    L.append(hc_http(s.port, s.health_path) if s.health_path else
             f"HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \\\n  CMD nc -z 127.0.0.1 {s.port} || exit 1")
    L += labels(s, ctx) + [f"ENTRYPOINT {jq(entry)}"]
    return "\n".join(L) + "\n"


def gen_python(s: Service, ctx: Ctx) -> str:
    dd, v = s.data, s.version
    base = ctx.img("python", v=v)
    pip_mounts = ["--mount=type=cache,target=/root/.cache/pip",
                  "--mount=type=secret,id=pipconf,target=/etc/pip.conf,required=false"]
    L = header(s) + [f"FROM {base} AS builder",
                     "ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_DEFAULT_TIMEOUT=100",
                     run(["apt-get update", "apt-get install -y --no-install-recommends build-essential " + " ".join(dd["build_pkgs"]),
                          "rm -rf /var/lib/apt/lists/*"]).replace("  ", " "),
                     "RUN python -m venv /opt/venv", 'ENV PATH="/opt/venv/bin:$PATH"', "WORKDIR /build"]
    mgr = dd["mgr"]
    if mgr == "poetry":
        L += ["COPY pyproject.toml poetry.lock ./",
              run(["pip install poetry poetry-plugin-export", "poetry export --only main --without-hashes -o requirements.txt",
                   "pip install -r requirements.txt"], pip_mounts)]
    elif mgr == "uv":
        L += ["COPY pyproject.toml uv.lock ./",
              run(["pip install uv", "uv export --frozen --no-dev --no-hashes --no-emit-project -o requirements.txt",
                   "pip install -r requirements.txt"], pip_mounts)]
    elif mgr == "pipenv":
        L += ["COPY Pipfile Pipfile.lock ./",
              run(["pip install pipenv", "pipenv requirements > requirements.txt", "pip install -r requirements.txt"], pip_mounts)]
    elif mgr == "pyproject":
        L += ["COPY . .", run(["pip install ."], pip_mounts)]
    else:
        L += ["COPY requirements.txt ./", run(["pip install -r requirements.txt"], pip_mounts)]
    server = dd.get("server")
    if server == "gunicorn" and not dd["gunicorn"]:
        L.append(run(["pip install gunicorn"], pip_mounts) + "  # not in your deps")
    if server == "uvicorn" and not dd["uvicorn"]:
        L.append(run(["pip install 'uvicorn[standard]'"], pip_mounts) + "  # not in your deps")

    L += ["", f"FROM {base} AS runtime",
          'ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONFAULTHANDLER=1 PATH="/opt/venv/bin:$PATH"']
    extra = dd["runtime_pkgs"] + list(s.cfg.get("apt_packages", []))
    if extra:
        L.append(run(["apt-get update", "apt-get install -y --no-install-recommends " + " ".join(extra),
                      "rm -rf /var/lib/apt/lists/*"]))
    L += [debian_user(), "WORKDIR /app", "COPY --from=builder /opt/venv /opt/venv", f"COPY --chown={UID}:{UID} . /app"]
    if dd.get("collectstatic"):
        L.append("# Build-time only dummy key; real secrets come from the runtime environment.\n"
                 "RUN SECRET_KEY=build-only DJANGO_SECRET_KEY=build-only python manage.py collectstatic --noinput")
    L += [f"EXPOSE {s.port}", f"USER {UID}:{UID}"]
    if s.health_path:
        L.append("HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 \\\n  CMD " + jq([
            "python", "-c", f"import urllib.request; urllib.request.urlopen('http://127.0.0.1:{s.port}{s.health_path}', timeout=2)"]))
    else:
        L.append("HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 \\\n  CMD " + jq([
            "python", "-c", f"import socket; socket.create_connection(('127.0.0.1', {s.port}), 2)"]))
    L += labels(s, ctx) + [f"CMD {jq(s.data.get('entry_override', dd['cmd']))}"]
    return "\n".join(L) + "\n"


def gen_go(s: Service, ctx: Ctx) -> str:
    dd = s.data
    mod = ["--mount=type=cache,target=/go/pkg/mod", "--mount=type=secret,id=netrc,target=/root/.netrc,required=false"]
    L = header(s) + [f"FROM --platform=$BUILDPLATFORM {ctx.img('golang', v=s.version)} AS build",
                     "ARG TARGETOS", "ARG TARGETARCH", "RUN apk add --no-cache git ca-certificates", "WORKDIR /src",
                     "COPY go.mod go.sum* ./"]
    if not dd["vendor"]:
        L.append(run(["go mod download"], mod))
    L.append("COPY . .")
    flags = "-mod=vendor " if dd["vendor"] else ""
    L.append(run([f'CGO_ENABLED=0 GOOS=${{TARGETOS:-linux}} GOARCH=${{TARGETARCH:-amd64}} go build {flags}-trimpath -ldflags="-s -w" -o /out/app {dd["pkg"]}'],
                 ["--mount=type=cache,target=/go/pkg/mod", "--mount=type=cache,target=/root/.cache/go-build"]))
    L += ["", f"FROM {ctx.img('distroless_static')} AS runtime",
          "# distroless/static: no shell, no package manager, CA certs + tzdata only. Use K8s probes for health.",
          "COPY --from=build --chown=65532:65532 /out/app /app", f"EXPOSE {s.port}", "USER 65532:65532"]
    L += labels(s, ctx) + [f"ENTRYPOINT {jq(s.data.get('entry_override', ['/app']))}"]
    return "\n".join(L) + "\n"


def gen_dotnet(s: Service, ctx: Ctx) -> str:
    dd, v = s.data, s.version
    modern = float(v) >= 8.0
    nuget = ["--mount=type=cache,target=/root/.nuget/packages",
             "--mount=type=secret,id=nuget_config,target=/root/.nuget/NuGet/NuGet.Config,required=false"]
    L = header(s) + [f"FROM {ctx.img('dotnet_sdk', v=v)} AS build", "WORKDIR /src"]
    for f in dd["restore"]:
        parent = str(Path(f).parent.as_posix())
        L.append(f"COPY {jq([f, './' if parent == '.' else parent + '/'])}")
    L += [run([f'dotnet restore "{dd["proj"]}"'], nuget), "COPY . .",
          run([f'dotnet publish "{dd["proj"]}" -c Release -o /app/publish --no-restore /p:UseAppHost=false'], nuget), ""]
    if dd["web"]:
        rt = ctx.img("dotnet_aspnet_chiseled" if modern else "dotnet_aspnet", v=v)
    else:
        rt = ctx.img("dotnet_runtime_chiseled" if modern else "dotnet_runtime", v=v)
    L += [f"FROM {rt} AS runtime", "WORKDIR /app"]
    if modern:
        L.append("# Chiseled image: non-root by default, no shell/package manager. Use K8s probes for health.")
        L.append(f"ENV ASPNETCORE_HTTP_PORTS={s.port} DOTNET_EnableDiagnostics=0")
    else:
        L += [debian_user(), f"ENV ASPNETCORE_URLS=http://+:{s.port} DOTNET_EnableDiagnostics=0"]
    L += ["COPY --from=build /app/publish .", f"EXPOSE {s.port}", f"USER {'$APP_UID' if modern else str(UID) + ':' + str(UID)}"]
    L += labels(s, ctx) + [f"ENTRYPOINT {jq(s.data.get('entry_override', ['dotnet', dd['asm'] + '.dll']))}"]
    return "\n".join(L) + "\n"


NPM_MOUNTS = ["--mount=type=secret,id=npmrc,target=/root/.npmrc,required=false"]


def node_install(mgr: str) -> (List[str], str, List[str]):
    """returns (pre-commands, install cmd, mounts)"""
    if mgr == "pnpm":
        return ["corepack enable pnpm"], "pnpm install --frozen-lockfile", ["--mount=type=cache,target=/root/.local/share/pnpm/store"] + NPM_MOUNTS
    if mgr == "yarn-berry":
        return ["corepack enable yarn"], "yarn install --immutable", ["--mount=type=cache,target=/root/.yarn/berry/cache"] + NPM_MOUNTS
    if mgr == "yarn":
        return ["corepack enable yarn"], "yarn install --frozen-lockfile", ["--mount=type=cache,target=/usr/local/share/.cache/yarn"] + NPM_MOUNTS
    if mgr == "npm-nolock":
        return [], "npm install", ["--mount=type=cache,target=/root/.npm"] + NPM_MOUNTS
    return [], "npm ci", ["--mount=type=cache,target=/root/.npm"] + NPM_MOUNTS


def node_script(mgr: str, name: str) -> str:
    return {"pnpm": f"pnpm run {name}", "yarn": f"yarn {name}", "yarn-berry": f"yarn {name}"}.get(mgr, f"npm run {name}")


def gen_node(s: Service, ctx: Ctx) -> str:
    dd, v = s.data, s.version
    pre, install, mounts = node_install(dd["mgr"])
    node = ctx.img("node", v=v)
    L = header(s) + [f"FROM {node} AS build", "WORKDIR /app"]
    L.append("COPY package.json " + " ".join(f for f in dd["lock"] if f != "package.json") + " ./")
    L.append(run(pre + [install], mounts))
    L.append("COPY . .")
    if dd["has_build"]:
        L.append(f"RUN {node_script(dd['mgr'], 'build')}")
    kind = dd["kind"]
    if kind == "spa":
        L += ["", f"FROM {ctx.img('nginx')} AS runtime",
              "# nginx-unprivileged: runs as uid 101 on :8080, no root needed.",
              "COPY nginx.conf /etc/nginx/conf.d/default.conf", f"COPY --from=build /app/{dd['out']}/ /usr/share/nginx/html/",
              "EXPOSE 8080", "USER 101", hc_http(8080, "/healthz")] + labels(s, ctx)
        s.files["nginx.conf"] = nginx_conf()
        return "\n".join(L) + "\n"
    L += ["", f"FROM {node} AS runtime", "ENV NODE_ENV=production", "RUN apk add --no-cache tini", "WORKDIR /app"]
    if kind == "next" and dd["standalone"]:
        L += ["ENV NEXT_TELEMETRY_DISABLED=1 HOSTNAME=0.0.0.0 PORT=" + str(s.port),
              "COPY --from=build --chown=1000:1000 /app/.next/standalone ./",
              "COPY --from=build --chown=1000:1000 /app/.next/static ./.next/static"]
        if dd["public"]:
            L.append("COPY --from=build --chown=1000:1000 /app/public ./public")
        entry = ["node", "server.js"]
    else:
        prune = {"pnpm": "pnpm prune --prod", "npm": "npm prune --omit=dev", "npm-nolock": "npm prune --omit=dev",
                 "yarn": "yarn install --production --frozen-lockfile"}.get(dd["mgr"])
        if prune:  # prune in build stage so the runtime copy has prod deps only
            idx = L.index("COPY . .")
            L.insert(idx + 2 if dd["has_build"] else idx + 1, run(pre + [prune], mounts))
        L.append("COPY --from=build --chown=1000:1000 /app /app")
        entry = dd["entry"] or ["node", "node_modules/next/dist/bin/next", "start", "-p", str(s.port)]
        if kind == "next":
            entry = ["node", "node_modules/next/dist/bin/next", "start", "-p", str(s.port)]
    entry = s.data.get("entry_override", entry)
    L += [f"EXPOSE {s.port}", "USER 1000:1000"]
    p = s.health_path
    chk = (f"http.get('http://127.0.0.1:{s.port}{p}', r => process.exit(r.statusCode < 400 ? 0 : 1)).on('error', () => process.exit(1))"
           if p else f"require('net').connect({s.port}, '127.0.0.1').on('connect', () => process.exit(0)).on('error', () => process.exit(1))")
    chk = "const http = require('http'); " + chk if p else chk
    L.append("HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 \\\n  CMD " + jq(["node", "-e", chk]))
    L += labels(s, ctx) + [f'ENTRYPOINT ["/sbin/tini", "--"]', f"CMD {jq(entry)}"]
    return "\n".join(L) + "\n"


def nginx_conf() -> str:
    sec = ('        add_header X-Content-Type-Options "nosniff" always;\n'
           '        add_header X-Frame-Options "DENY" always;\n'
           '        add_header Referrer-Policy "strict-origin-when-cross-origin" always;\n'
           '        add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;\n'
           '        # add_header Content-Security-Policy "default-src \'self\'; frame-ancestors \'none\'" always;  # tune per app\n')
    return f"""{MARKER}
server {{
    listen 8080;
    server_name _;
    root /usr/share/nginx/html;
    index index.html;
    server_tokens off;

{sec.replace('        ', '    ')}
    gzip on;
    gzip_types text/css application/javascript application/json image/svg+xml;

    location = /healthz {{
        access_log off;
        default_type text/plain;
        return 200 "ok\\n";
    }}

    # Hashed build assets: cache forever. (add_header in a location replaces inherited ones, so repeat.)
    location ~* \\.(?:js|css|woff2?|png|jpe?g|gif|svg|ico|webp)$ {{
        expires 1y;
        add_header Cache-Control "public, immutable";
{sec}    }}

    location / {{
        try_files $uri $uri/ /index.html;
        add_header Cache-Control "no-cache";
{sec}    }}
}}
"""


GENERATORS = {"java": gen_java, "python": gen_python, "go": gen_go, "dotnet": gen_dotnet, "node": gen_node}

DOCKERIGNORE = f"""{MARKER}
.git
.github
.gitlab-ci.yml
.idea
.vscode
**/.DS_Store
# secrets & local config - never send to the build context
.env
.env.*
!.env.example
*.pem
*.key
*.p12
*.pfx
id_rsa*
.aws
.ssh
# build output / caches
**/node_modules
**/target
**/build
**/dist
**/bin
**/obj
**/__pycache__
**/*.pyc
.venv
venv
.gradle
.next
coverage
# docker / local artefacts
Dockerfile*
docker-compose*.yml
*.log
"""


# --------------------------------------------------------------------------- compose
def yaml_scalar(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    return json.dumps(str(v), ensure_ascii=False)


def to_yaml(obj, ind: int = 0) -> str:
    pad, out = "  " * ind, []
    for k, v in obj.items():
        if isinstance(v, dict):
            out += [f"{pad}{k}:" if v else f"{pad}{k}: {{}}"] + ([to_yaml(v, ind + 1)] if v else [])
        elif isinstance(v, list):
            out.append(f"{pad}{k}: {json.dumps(v, ensure_ascii=False)}")
        else:
            out.append(f"{pad}{k}: {yaml_scalar(v)}")
    return "\n".join(out)


HARDEN = {"security_opt": ["no-new-privileges:true"], "cap_drop": ["ALL"],
          "logging": {"driver": "json-file", "options": {"max-size": "10m", "max-file": "3"}},
          "restart": "unless-stopped"}
HC = {"interval": "10s", "timeout": "5s", "retries": 10, "start_period": "20s"}
DB_CAPS = ["CHOWN", "SETGID", "SETUID", "DAC_OVERRIDE", "FOWNER"]  # entrypoints drop privileges via gosu


def infra_defs() -> Dict[str, dict]:
    def base(image: str, **kw) -> dict:
        d = {"image": image, **HARDEN, "networks": ["data"]}
        d.update(kw)
        return d
    return {
        "postgres": base("postgres:17-alpine", cap_add=DB_CAPS,
                         environment={"POSTGRES_USER": "${POSTGRES_USER:-app}",
                                      "POSTGRES_PASSWORD": "${POSTGRES_PASSWORD:?set POSTGRES_PASSWORD in .env}"},
                         volumes=["postgres-data:/var/lib/postgresql/data",
                                  "./infra/postgres/init-databases.sh:/docker-entrypoint-initdb.d/10-init-databases.sh:ro"],
                         healthcheck={"test": ["CMD-SHELL", "pg_isready -U $${POSTGRES_USER}"], **HC}),
        "mysql": base("mysql:8.4", cap_add=DB_CAPS,
                      environment={"MYSQL_ROOT_PASSWORD": "${MYSQL_ROOT_PASSWORD:?set MYSQL_ROOT_PASSWORD in .env}",
                                   "MYSQL_USER": "${MYSQL_USER:-app}",
                                   "MYSQL_PASSWORD": "${MYSQL_PASSWORD:?set MYSQL_PASSWORD in .env}"},
                      volumes=["mysql-data:/var/lib/mysql",
                               "./infra/mysql/init-databases.sh:/docker-entrypoint-initdb.d/10-init-databases.sh:ro"],
                      healthcheck={"test": ["CMD-SHELL", "mysqladmin ping -h 127.0.0.1 -uroot -p$${MYSQL_ROOT_PASSWORD} --silent"], **HC}),
        "redis": base("redis:7-alpine", cap_add=DB_CAPS,
                      environment={"REDIS_PASSWORD": "${REDIS_PASSWORD:?set REDIS_PASSWORD in .env}"},
                      command=["sh", "-c", "exec redis-server --requirepass \"$$REDIS_PASSWORD\" --appendonly yes"],
                      volumes=["redis-data:/data"],
                      healthcheck={"test": ["CMD-SHELL", "REDISCLI_AUTH=$$REDIS_PASSWORD redis-cli ping | grep -q PONG"], **HC}),
        "memcached": base("memcached:1.6-alpine", command=["-m", "64"], read_only=True,
                          healthcheck={"test": ["CMD-SHELL", "nc -z 127.0.0.1 11211"], **HC}),
        "kafka": base("apache/kafka:3.9.0",
                      environment={"KAFKA_NODE_ID": "1", "KAFKA_PROCESS_ROLES": "broker,controller",
                                   "KAFKA_LISTENERS": "PLAINTEXT://:9092,CONTROLLER://:9093",
                                   "KAFKA_ADVERTISED_LISTENERS": "PLAINTEXT://kafka:9092",
                                   "KAFKA_CONTROLLER_LISTENER_NAMES": "CONTROLLER",
                                   "KAFKA_LISTENER_SECURITY_PROTOCOL_MAP": "CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT",
                                   "KAFKA_CONTROLLER_QUORUM_VOTERS": "1@kafka:9093",
                                   "KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR": "1",
                                   "KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR": "1",
                                   "KAFKA_TRANSACTION_STATE_LOG_MIN_ISR": "1",
                                   "KAFKA_GROUP_INITIAL_REBALANCE_DELAY_MS": "0"},
                      volumes=["kafka-data:/var/lib/kafka/data"],
                      healthcheck={"test": ["CMD-SHELL", "/opt/kafka/bin/kafka-broker-api-versions.sh --bootstrap-server localhost:9092 >/dev/null 2>&1"],
                                   **{**HC, "start_period": "40s"}}),
        "mongodb": base("mongo:7", cap_add=DB_CAPS,
                        environment={"MONGO_INITDB_ROOT_USERNAME": "${MONGO_USER:-app}",
                                     "MONGO_INITDB_ROOT_PASSWORD": "${MONGO_PASSWORD:?set MONGO_PASSWORD in .env}"},
                        volumes=["mongo-data:/data/db"],
                        healthcheck={"test": ["CMD-SHELL", "mongosh --quiet --eval \"db.adminCommand('ping')\" >/dev/null"], **HC}),
        "rabbitmq": base("rabbitmq:3.13-alpine",
                         environment={"RABBITMQ_DEFAULT_USER": "${RABBITMQ_USER:-app}",
                                      "RABBITMQ_DEFAULT_PASS": "${RABBITMQ_PASSWORD:?set RABBITMQ_PASSWORD in .env}"},
                         volumes=["rabbitmq-data:/var/lib/rabbitmq"],
                         healthcheck={"test": ["CMD-SHELL", "rabbitmq-diagnostics -q ping"], **HC}),
    }


INFRA_VOLUMES = {"postgres": "postgres-data", "mysql": "mysql-data", "redis": "redis-data", "kafka": "kafka-data",
                 "mongodb": "mongo-data", "rabbitmq": "rabbitmq-data"}
ENV_VARS = {
    "postgres": ["POSTGRES_USER=app", "POSTGRES_PASSWORD="], "mysql": ["MYSQL_USER=app", "MYSQL_ROOT_PASSWORD=", "MYSQL_PASSWORD="],
    "redis": ["REDIS_PASSWORD="], "mongodb": ["MONGO_USER=app", "MONGO_PASSWORD="], "rabbitmq": ["RABBITMQ_USER=app", "RABBITMQ_PASSWORD="],
}


def app_env(s: Service) -> Dict[str, str]:
    e: Dict[str, str] = {}
    db = s.name.replace("-", "_")
    spring, dotnet = s.framework == "springboot", s.language == "dotnet"
    pg = "${POSTGRES_USER:-app}:${POSTGRES_PASSWORD}"
    if "postgres" in s.infra:
        e.update({"DB_HOST": "postgres", "DB_PORT": "5432", "DB_NAME": db, "DB_USER": "${POSTGRES_USER:-app}",
                  "DB_PASSWORD": "${POSTGRES_PASSWORD}", "DATABASE_URL": f"postgresql://{pg}@postgres:5432/{db}"})
        if spring:
            e.update({"SPRING_DATASOURCE_URL": f"jdbc:postgresql://postgres:5432/{db}", "SPRING_DATASOURCE_USERNAME": "${POSTGRES_USER:-app}",
                      "SPRING_DATASOURCE_PASSWORD": "${POSTGRES_PASSWORD}"})
        if dotnet:
            e["ConnectionStrings__DefaultConnection"] = f"Host=postgres;Port=5432;Database={db};Username=${{POSTGRES_USER:-app}};Password=${{POSTGRES_PASSWORD}}"
    elif "mysql" in s.infra:
        e.update({"DB_HOST": "mysql", "DB_PORT": "3306", "DB_NAME": db, "DB_USER": "${MYSQL_USER:-app}", "DB_PASSWORD": "${MYSQL_PASSWORD}",
                  "DATABASE_URL": f"mysql://${{MYSQL_USER:-app}}:${{MYSQL_PASSWORD}}@mysql:3306/{db}"})
        if spring:
            e.update({"SPRING_DATASOURCE_URL": f"jdbc:mysql://mysql:3306/{db}", "SPRING_DATASOURCE_USERNAME": "${MYSQL_USER:-app}",
                      "SPRING_DATASOURCE_PASSWORD": "${MYSQL_PASSWORD}"})
        if dotnet:
            e["ConnectionStrings__DefaultConnection"] = f"Server=mysql;Port=3306;Database={db};User=${{MYSQL_USER:-app}};Password=${{MYSQL_PASSWORD}}"
    if "redis" in s.infra:
        e.update({"REDIS_HOST": "redis", "REDIS_PORT": "6379", "REDIS_PASSWORD": "${REDIS_PASSWORD}", "REDIS_URL": "redis://:${REDIS_PASSWORD}@redis:6379/0"})
        if spring:
            e.update({"SPRING_DATA_REDIS_HOST": "redis", "SPRING_DATA_REDIS_PASSWORD": "${REDIS_PASSWORD}",
                      "SPRING_REDIS_HOST": "redis", "SPRING_REDIS_PASSWORD": "${REDIS_PASSWORD}"})
        if dotnet:
            e["ConnectionStrings__Redis"] = "redis:6379,password=${REDIS_PASSWORD}"
    if "memcached" in s.infra:
        e.update({"MEMCACHED_HOST": "memcached", "MEMCACHED_PORT": "11211"})
    if "kafka" in s.infra:
        e["KAFKA_BOOTSTRAP_SERVERS"] = "kafka:9092"
        if spring:
            e["SPRING_KAFKA_BOOTSTRAP_SERVERS"] = "kafka:9092"
        if dotnet:
            e["Kafka__BootstrapServers"] = "kafka:9092"
    if "mongodb" in s.infra:
        e["MONGODB_URI"] = f"mongodb://${{MONGO_USER:-app}}:${{MONGO_PASSWORD}}@mongodb:27017/{db}?authSource=admin"
    if "rabbitmq" in s.infra:
        e["AMQP_URL"] = "amqp://${RABBITMQ_USER:-app}:${RABBITMQ_PASSWORD}@rabbitmq:5672/"
    return e


def build_compose(services: List[Service], base_port: int) -> Dict[str, str]:
    used = set().union(*[s.infra for s in services]) if services else set()
    defs = infra_defs()
    svc: Dict[str, dict] = {}
    for k in ["postgres", "mysql", "redis", "memcached", "kafka", "mongodb", "rabbitmq"]:
        if k in used:
            svc[k] = defs[k]
    for i, s in enumerate(services):
        jvm = s.language == "java"
        d = {
            "image": f"${{REGISTRY:-local}}/{s.name}:${{TAG:-dev}}",
            "build": {"context": f"./{s.rel}" if s.rel != "." else ".", "dockerfile": "Dockerfile",
                      "args": {"VCS_REF": "${VCS_REF:-local}"}},
            **HARDEN, "init": True, "read_only": True,
            # JVM native libs (netty, snappy) need an executable /tmp, everything else gets noexec.
            "tmpfs": ["/tmp:rw,nosuid,size=128m" if jvm else "/tmp:rw,noexec,nosuid,size=64m"],
            "pids_limit": 512,
            "deploy": {"resources": {"limits": {"cpus": "1.0", "memory": "768M" if jvm else "512M"}}},
        }
        env = app_env(s)
        if env:
            d["environment"] = env
        d["ports"] = [f"127.0.0.1:{base_port + i}:{s.port}"]
        deps = {k: {"condition": "service_healthy"} for k in s.infra if k in svc}
        if deps:
            d["depends_on"] = deps
        d["networks"] = ["edge"] + (["data"] if deps else [])
        svc[s.name] = d
    vols = [INFRA_VOLUMES[k] for k in INFRA_VOLUMES if k in used]
    doc = ("# Generated by dockergen - LOCAL DEV / INTEGRATION TESTING ONLY. Production runs on Kubernetes/ECS.\n"
           "# Requires a .env (see .env.example). Infra sits on an internal-only network; apps publish on 127.0.0.1.\n")
    top = {"name": "microservices", "services": None}
    out = doc + "name: microservices\nservices:\n"
    for n, d in svc.items():
        out += f"  {n}:\n{to_yaml(d, 2)}\n"
    out += "networks:\n  edge: {}\n"
    if used:
        out += "  data:\n    internal: true\n"
    if vols:
        out += "volumes:\n" + "".join(f"  {v}: {{}}\n" for v in vols)

    files = {"docker-compose.yml": out}
    env_lines = ["# Copy to .env and fill in. Generate secrets with: openssl rand -base64 24", "REGISTRY=local", "TAG=dev", "VCS_REF=local"]
    for k in INFRA_VOLUMES:
        env_lines += ENV_VARS.get(k, [])
    files[".env.example"] = "\n".join(env_lines) + "\n"
    if "postgres" in used:
        names = " ".join(s.name.replace("-", "_") for s in services if "postgres" in s.infra)
        files["infra/postgres/init-databases.sh"] = (
            "#!/bin/sh\n# one database per service (runs on first start only)\nset -eu\n"
            f"for db in {names}; do\n  psql -v ON_ERROR_STOP=1 --username \"$POSTGRES_USER\" --dbname postgres -c \"CREATE DATABASE \\\"$db\\\"\"\ndone\n")
    if "mysql" in used:
        names = " ".join(s.name.replace("-", "_") for s in services if "mysql" in s.infra and "postgres" not in s.infra)
        files["infra/mysql/init-databases.sh"] = (
            "#!/bin/sh\nset -eu\n"
            f"for db in {names}; do\n  mysql -uroot -p\"$MYSQL_ROOT_PASSWORD\" -e \"CREATE DATABASE IF NOT EXISTS \\`$db\\`; GRANT ALL ON \\`$db\\`.* TO '$MYSQL_USER'@'%';\"\ndone\n")
    return files


# --------------------------------------------------------------------------- IO
def write_managed(path: Path, content: str, args, status: Dict[str, List[str]], label: str) -> None:
    exists = path.exists()
    managed = exists and MARKER in read(path, 2000)
    if exists and not managed and not args.force:
        status["skipped"].append(f"{label} (hand-written; use --force)")
        return
    if exists and read(path) == content:
        status["unchanged"].append(label)
        return
    if args.check:
        status["drift"].append(label)
        return
    if args.dry_run:
        status["would_write"].append(label)
        return
    if exists and not managed:
        path.with_name(path.name + ".bak").write_text(read(path, 10_000_000), encoding="utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    status["written"].append(label)


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate hardened Dockerfiles (and compose) by analysing service code.")
    ap.add_argument("root", nargs="?", default=".", help="repo root, or the root of a monorepo of services")
    ap.add_argument("--depth", type=int, default=3, help="how deep to look for services (default 3)")
    ap.add_argument("--only", help="comma-separated service names to process")
    ap.add_argument("--force", action="store_true", help="overwrite hand-written Dockerfiles (backs up as .bak)")
    ap.add_argument("--check", action="store_true", help="CI mode: write nothing, exit 1 if managed files are missing/outdated")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--compose", action="store_true", help="also generate docker-compose.yml, .env.example, infra init scripts")
    ap.add_argument("--base-port", type=int, default=18000, help="first host port for compose (default 18000)")
    ap.add_argument("--base-registry", default="", help="prefix base images with your internal mirror, e.g. registry.corp/dockerhub")
    ap.add_argument("--digests", help="JSON file {\"python:3.12-slim\": \"sha256:...\"} to pin base images by digest")
    ap.add_argument("--vendor", default="", help="org.opencontainers.image.vendor label value")
    ap.add_argument("--report", default="dockergen-report.json")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    ctx = Ctx(registry=args.base_registry, vendor=args.vendor)
    if args.digests:
        ctx.digests = json.loads(read(Path(args.digests)))

    services = discover(root, args.depth)
    if args.only:
        wanted = {x.strip() for x in args.only.split(",")}
        services = [s for s in services if s.name in wanted]
    if not services:
        print("No services detected.", file=sys.stderr)
        return 2

    status: Dict[str, List[str]] = {k: [] for k in ("written", "unchanged", "skipped", "drift", "would_write")}
    report = []
    print(f"{'SERVICE':34} {'STACK':26} {'PORT':>5}  INFRA")
    for s in services:
        try:
            dockerfile = GENERATORS[s.language](s, ctx)
        except Exception as e:  # keep going across 300 services
            print(f"{s.name:34} ERROR {e}", file=sys.stderr)
            continue
        write_managed(s.path / "Dockerfile", dockerfile, args, status, f"{s.rel}/Dockerfile")
        write_managed(s.path / ".dockerignore", DOCKERIGNORE, args, status, f"{s.rel}/.dockerignore")
        for fn, content in s.files.items():
            write_managed(s.path / fn, content, args, status, f"{s.rel}/{fn}")
        stack = f"{s.framework} ({s.language} {s.version})"
        print(f"{s.name:34} {stack:26} {s.port:>5}  {','.join(sorted(s.infra)) or '-'}")
        for n in s.notes:
            print(f"    ! {n}")
        report.append({"service": s.name, "path": s.rel, "language": s.language, "framework": s.framework, "version": s.version,
                       "port": s.port, "health_path": s.health_path, "infra": sorted(s.infra), "notes": s.notes})

    if args.compose:
        for fn, content in build_compose(services, args.base_port).items():
            write_managed(root / fn, content if fn.endswith((".yml", ".example")) else content, args, status, fn)
            if fn.endswith(".sh") and not (args.check or args.dry_run):
                os.chmod(root / fn, 0o755)
    if not (args.check or args.dry_run):
        (root / args.report).write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("\n" + ", ".join(f"{k}: {len(v)}" for k, v in status.items() if v))
    for item in status["skipped"]:
        print(f"  skipped {item}")
    if args.check and status["drift"]:
        print("\nDRIFT detected (re-run dockergen and commit):", *status["drift"], sep="\n  ", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
