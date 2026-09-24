"""Repository-first inventory. Files are always treated as untrusted data."""
from __future__ import annotations
import json, os, re, hashlib, fnmatch, tomllib
import importlib.util
from collections import Counter, defaultdict
from pathlib import Path
from typing import Protocol

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build", "target", ".venv", "venv", "__pycache__", ".next", "coverage", ".terraform"}
MANIFESTS = {
 "package.json":"JavaScript/TypeScript", "composer.json":"PHP", "requirements.txt":"Python", "pyproject.toml":"Python", "Pipfile":"Python", "pom.xml":"Java", "build.gradle":"Java/Kotlin", "build.gradle.kts":"Kotlin/Java", "go.mod":"Go", "Cargo.toml":"Rust", "Gemfile":"Ruby", "mix.exs":"Elixir", "pubspec.yaml":"Dart/Flutter", "Package.swift":"Swift", "CMakeLists.txt":"C/C++", "Dockerfile":"Docker", "Chart.yaml":"Kubernetes/Helm", "terraform.tf":"Terraform", "main.tf":"Terraform", "*.csproj":"C#/.NET", "*.sln":"C#/.NET", "*.tf":"Terraform"
}
EXT_LANG = {".py":"Python", ".pyi":"Python", ".js":"JavaScript", ".jsx":"JavaScript", ".mjs":"JavaScript", ".cjs":"JavaScript", ".ts":"TypeScript", ".tsx":"TypeScript", ".java":"Java", ".kt":"Kotlin", ".kts":"Kotlin", ".php":"PHP", ".go":"Go", ".rs":"Rust", ".rb":"Ruby", ".ex":"Elixir", ".exs":"Elixir", ".cs":"C#", ".fs":"F#", ".swift":"Swift", ".dart":"Dart", ".c":"C", ".h":"C/C++", ".cc":"C++", ".cpp":"C++", ".hpp":"C++", ".sql":"SQL", ".sh":"Shell", ".bash":"Shell", ".tf":"Terraform", ".yml":"YAML", ".yaml":"YAML", ".dockerfile":"Docker", ".html":"HTML", ".css":"CSS", ".scss":"CSS", ".vue":"Vue SFC", ".svelte":"Svelte"}
ADAPTER_DIR = Path(__file__).parent / "framework_adapters"

def _load_adapters():
    adapters=[]
    if not ADAPTER_DIR.exists(): return adapters
    for source in ADAPTER_DIR.glob("*.py"):
        if source.name.startswith("_"): continue
        try:
            spec=importlib.util.spec_from_file_location(f"repository_adapter_{source.stem}",source)
            module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
            adapter=module.get_adapter() if hasattr(module,"get_adapter") else module.Adapter()
            if callable(getattr(adapter,"detect",None)): adapters.append(adapter)
        except Exception:
            continue
    return adapters

class ParserInterface(Protocol):
    def parse(self, source: str, path: str) -> dict: ...

class FrameworkAdapter(Protocol):
    """Optional adapter contract. Implement only what the framework can evidence."""
    name: str
    def detect(self, root: Path, manifests: list[str]) -> float: ...
    def get_entry_points(self, root: Path) -> list[dict]: ...
    def get_routes(self, root: Path) -> list[dict]: ...
    def get_models(self, root: Path) -> list[dict]: ...
    def get_controllers(self, root: Path) -> list[dict]: ...
    def get_services(self, root: Path) -> list[dict]: ...
    def get_config(self, root: Path) -> list[dict]: ...
    def get_tests(self, root: Path) -> list[dict]: ...
    def get_conventions(self) -> dict: ...

class LanguageParser:
    """A grammar-neutral symbol/import extractor with optional Tree-sitter availability."""
    def parse(self, source: str, path: str) -> dict:
        ext = Path(path).suffix.lower()
        language = EXT_LANG.get(ext, "unknown")
        definitions = []
        patterns = [
          (r"^\s*(?:async\s+)?def\s+([\w$]+)\s*\(", "function"),
          (r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([\w$]+)", "function"),
          (r"^\s*(?:export\s+)?(?:abstract\s+)?class\s+([\w$]+)", "class"),
          (r"^\s*(?:public|private|protected|static|final|async|override|func|fn|fun|sub|def|function|void|int|bool|String|Task[\w<>?, ]*)+\s+([\w$]+)\s*\(", "method"),
          (r"^\s*(?:export\s+)?(?:const|let|var)\s+([\w$]+)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[\w$]+)\s*=>", "function"),
          (r"^\s*(?:func|fn|fun)\s+([\w$]+)", "function"),
        ]
        for number, line in enumerate(source.splitlines(), 1):
            for regex, kind in patterns:
                m = re.search(regex, line)
                if m:
                    definitions.append({"name":m.group(1), "kind":kind, "line":number}); break
        imports=[]
        for number, line in enumerate(source.splitlines(),1):
            m = re.match(r"\s*(?:import\s+(?:.*?\s+from\s+)?|from\s+([\w.]+)\s+import\s+|require\(['\"])([\w./@-]+)", line)
            if m:
                imports.append({"name":next((x for x in m.groups() if x), ""), "line":number})
            else:
                m=re.match(r"\s*use\s+([\w\\]+)|\s*#include\s*[<\"]([^>\"]+)",line)
                if m: imports.append({"name":next((x for x in m.groups() if x), ""),"line":number})
        tree_sitter = False
        try:
            from tree_sitter_language_pack import get_parser
            grammar = {"Python":"python","JavaScript":"javascript","TypeScript":"typescript","Java":"java","Go":"go","Rust":"rust","PHP":"php","Ruby":"ruby","C#":"c_sharp","C":"c","C++":"cpp","Kotlin":"kotlin","Swift":"swift"}.get(language)
            if grammar:
                get_parser(grammar).parse(source.encode("utf-8", errors="replace")); tree_sitter = True
        except Exception:
            pass
        return {"language":language,"definitions":definitions,"imports":imports,"parser":"tree-sitter-available" if tree_sitter else "portable-fallback"}

class LanguageDetector:
    def detect(self, files: list[str], line_counts: Counter) -> list[dict]:
        counts=Counter()
        for name in files:
            p=Path(name); lang=EXT_LANG.get(p.suffix.lower())
            if not lang and p.name.lower().endswith("dockerfile"): lang="Docker"
            if lang: counts[lang]+=max(line_counts.get(name,1),1)
        total=sum(counts.values()) or 1
        return [{"name":name,"confidence":round(count/total,2),"evidence":"source file and line distribution"} for name,count in counts.most_common()]

class FrameworkDetector:
    """Small metadata/import signature set; unfamiliar frameworks remain analyzable."""
    SIGNATURES = {
      "django":["django"], "fastapi":["fastapi"], "flask":["flask"], "pyramid":["pyramid"],
      "laravel":["laravel/framework"], "symfony":["symfony/"], "wordpress":["wordpress"],
      "react":["react"], "next.js":["next"], "vue":["vue"], "nuxt":["nuxt"], "angular":["@angular/"], "express":["express"], "nestjs":["@nestjs/"], "svelte":["svelte"],
      "spring boot":["spring-boot-starter"], "quarkus":["quarkus"], "micronaut":["micronaut"],
      "asp.net core":["Microsoft.AspNetCore"], "rails":["rails"], "sinatra":["sinatra"],
    }
    def detect(self, manifest_text: str, source_text: str) -> list[dict]:
        hay=(manifest_text+"\n"+source_text).lower(); found=[]
        for name, tokens in self.SIGNATURES.items():
            matches=sum(hay.count(t.lower()) for t in tokens)
            if matches: found.append({"name":name,"confidence":min(.98,.60+.12*(matches-1)),"evidence":"dependency/import/config signature"})
        return sorted(found,key=lambda x:x["confidence"],reverse=True)

def _text(p: Path, limit: int) -> str | None:
    try:
        if p.stat().st_size > limit: return None
        raw=p.read_bytes()
        if b"\0" in raw[:8192]: return None
        return raw.decode("utf-8",errors="replace")
    except (OSError, PermissionError): return None

def _manifest_data(root: Path, files: list[str]) -> tuple[list[dict], str]:
    deps=[]; aggregate=[]
    for rel in files:
        p=root/rel; name=p.name
        if name not in {"package.json","composer.json","pyproject.toml","Cargo.toml","go.mod","Gemfile","pom.xml","requirements.txt","Pipfile","pubspec.yaml","Package.swift","mix.exs","build.gradle","build.gradle.kts"} and not name.endswith((".csproj",".sln",".tf")): continue
        content=_text(p,250_000)
        if content is None: continue
        aggregate.append(content)
        names=[]
        try:
            if name in {"package.json","composer.json"}:
                obj=json.loads(content); names=list(obj.get("dependencies",{}))+list(obj.get("devDependencies",{}))+list(obj.get("require",{}))+list(obj.get("require-dev",{}))
            elif name in {"pyproject.toml","Cargo.toml","Pipfile"}:
                obj=tomllib.loads(content)
                def walk(d):
                    out=[]
                    for key,val in d.items():
                        if isinstance(val,dict): out+=list(val.keys())
                    return out
                names=walk(obj.get("project",{}))+walk(obj.get("dependencies",{}))+walk(obj.get("tool",{}))+walk(obj.get("package",{}))
                project_deps=obj.get("project",{}).get("dependencies",[])
                if isinstance(project_deps,list): names += [re.split(r"[<>=!~\[]",x,1)[0].strip() for x in project_deps]
                names=list(dict.fromkeys(names))
            elif name=="go.mod": names=re.findall(r"(?m)^\s*([\w./-]+)\s+v[\w.+-]+",content)
            elif name=="Gemfile": names=re.findall(r"(?m)^\s*gem\s+['\"]([^'\"]+)",content)
            elif name in {"build.gradle","build.gradle.kts"}: names=re.findall(r"(?m)\b(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s*(?:\(|\s)[\"']([^\"']+)",content)
            elif name=="pubspec.yaml": names=re.findall(r"(?m)^\s{2}([A-Za-z0-9_.-]+)\s*:",content)
            elif name=="Package.swift": names=re.findall(r"\.package\s*\(\s*(?:url|name)\s*:\s*['\"]([^'\"]+)",content)
            elif name=="mix.exs": names=re.findall(r"\{\s*:([\w-]+)\s*,",content)
            elif name=="requirements.txt": names=[x.split(";")[0].split("[")[0].split("=")[0].split("<")[0].strip() for x in content.splitlines() if x and not x.lstrip().startswith("#")]
            elif name=="pom.xml": names=re.findall(r"<artifactId>([^<]+)</artifactId>",content)
            elif name.endswith(".csproj"): names=re.findall(r"PackageReference\s+Include=[\"']([^\"']+)",content)
            elif name.endswith(".tf"): names=re.findall(r"(?m)^\s*source\s*=\s*[\"']([^\"']+)",content)
        except Exception: pass
        deps.extend({"name":x,"manifest":rel,"ecosystem":name} for x in dict.fromkeys(names))
    return deps,"\n".join(aggregate)

def discover_repository(root: str | Path, max_files=20000, max_file_bytes=1_000_000, max_total_bytes=100_000_000) -> dict:
    root=Path(root).resolve(); files=[]
    for current, dirs, names in os.walk(root, followlinks=False):
        dirs[:]=[d for d in dirs if d not in SKIP_DIRS and not (Path(current)/d).is_symlink()]
        for name in names:
            path=Path(current)/name
            if path.is_symlink(): continue
            rel=path.relative_to(root).as_posix(); files.append(rel)
            if len(files)>=max_files: break
        if len(files)>=max_files: break
    files.sort(); line_counts=Counter(); contents={}; file_info=[]
    total_read=0
    for rel in files:
        p=root/rel; content=_text(p,max_file_bytes)
        if content is None: continue
        size=p.stat().st_size
        if total_read+size>max_total_bytes: continue
        total_read+=size
        contents[rel]=content; line_counts[rel]=max(1,content.count("\n")+1)
        file_info.append({"path":rel,"size_bytes":size,"sha256":hashlib.sha256(content.encode()).hexdigest(),"lines":line_counts[rel]})
    langs=LanguageDetector().detect(list(contents),line_counts)
    deps, manifest_text=_manifest_data(root,list(contents))
    sampled="\n".join(list(contents.values())[:100])[:500_000]
    frameworks=FrameworkDetector().detect(manifest_text,sampled)
    adapters=_load_adapters(); adapter_results=[]
    for adapter in adapters:
        try:
            confidence=float(adapter.detect(root,[p for p in contents if Path(p).name in manifest_names]))
            if confidence>0:
                frameworks.append({"name":getattr(adapter,"name",type(adapter).__name__),"confidence":round(min(1,max(0,confidence)),2),"evidence":"optional framework adapter"})
            insight={"name":getattr(adapter,"name",type(adapter).__name__),"confidence":confidence}
            for method,key in (("get_entry_points","entry_points"),("get_routes","routes"),("get_models","models"),("get_controllers","controllers"),("get_services","services"),("get_config","config"),("get_tests","tests"),("get_conventions","conventions")):
                fn=getattr(adapter,method,None)
                if callable(fn): insight[key]=fn(root)
            adapter_results.append(insight)
        except Exception:
            continue
    if not frameworks and langs:
        frameworks=[{"name":"Unknown","confidence":0.72,"evidence":"No known framework signature was found; generic repository analysis remains enabled"}]
    framework_adapters=[getattr(a,"name",type(a).__name__) for a in adapters]
    parser=LanguageParser(); symbols=[]; relationships=[]; entry=[]; config=[]; tests=[]; dbuse=[]; external=[]; api=[]; auth=[]; jobs=[]; components=defaultdict(lambda:{"files":[],"languages":Counter(),"frameworks":[]})
    package_manifests={"package.json","composer.json","pyproject.toml","Cargo.toml","go.mod","Gemfile","pom.xml","requirements.txt","Pipfile","pubspec.yaml","Package.swift","mix.exs","build.gradle","build.gradle.kts"}
    manifest_paths=[x for x in contents if Path(x).name in package_manifests or x.endswith((".csproj",".sln",".tf"))]
    manifest_names={Path(x).name for x in manifest_paths}
    component_roots={Path(p).parent.as_posix() for p in contents if Path(p).name in package_manifests or p.endswith((".csproj",".tf"))}
    def component_for(rel):
        matches=[root for root in component_roots if root=="." and root!="" or rel==root or rel.startswith(root.rstrip(".")+"/")]
        return max(matches,key=len) if matches else "."
    for rel,text in contents.items():
        parsed=parser.parse(text,rel); lang=parsed["language"]
        for d in parsed["definitions"]: symbols.append({**d,"file":rel,"language":lang})
        for imp in parsed["imports"]: relationships.append({"source":rel,"target":imp["name"],"kind":"imports","line":imp["line"]})
        lower=rel.lower(); base=Path(rel).name.lower()
        if any(x in lower for x in ("test", "spec")) or base.startswith("test_"): tests.append({"file":rel,"kind":"test-file"})
        if any(x in lower for x in ("config", ".env", "settings", "application.", "values.yaml")): config.append({"file":rel,"kind":"configuration"})
        if base in {"dockerfile","compose.yml","docker-compose.yml","chart.yaml"} or lower.endswith((".tf",".tf.json")): config.append({"file":rel,"kind":"infrastructure"})
        if re.search(r"(?im)^\s*(?:if\s+__name__\s*==\s*['\"]__main__|func\s+main\s*\(|public\s+static\s+void\s+main|static\s+void\s+Main|int\s+main\s*\(|export\s+default|app\.run\(|uvicorn\.run\()",text): entry.append({"file":rel,"kind":"executable-entry-point","evidence":"main function or executable guard"})
        if re.search(r"(?i)(route|router|endpoint|@app\.(get|post|put|delete)|http\.handle|@GetMapping|@PostMapping)",text): api.append({"file":rel,"kind":"possible-api-definition"})
        if re.search(r"(?i)(password|credential|token|authorize|authentication|jwt|oauth)",text): auth.append({"file":rel,"kind":"auth-or-credential-reference"})
        if re.search(r"(?i)(select\s+.+\s+from|insert\s+into|\.execute\(|\.query\(|repository|database|\bdb\.)",text): dbuse.append({"file":rel,"kind":"database-or-query-reference"})
        if re.search(r"(?i)(https?://|requests\.|fetch\(|axios\.|http\.client|urlopen)",text): external.append({"file":rel,"kind":"external-service-reference"})
        if re.search(r"(?i)(celery|sidekiq|bullmq|@scheduled|cron|worker|consumer|kafka|rabbitmq)",text): jobs.append({"file":rel,"kind":"background-or-message-processing-reference"})
        top=component_for(rel); c=components[top]; c["files"].append(rel); c["languages"][lang]+=line_counts[rel]
    for name,comp in components.items():
        comp["languages"]={k:v for k,v in comp["languages"].most_common()}
        local_paths=comp["files"]
        local_manifest="\n".join(contents[x] for x in local_paths if Path(x).name in package_manifests or x.endswith((".csproj",".tf")))
        local_source="\n".join(contents[x] for x in local_paths[:100])
        local_frameworks=FrameworkDetector().detect(local_manifest,local_source)
        for adapter in adapters:
            try:
                confidence=float(adapter.detect(root if name=="." else root/name,[x for x in local_paths if Path(x).name in manifest_names]))
                if confidence>0: local_frameworks.append({"name":getattr(adapter,"name",type(adapter).__name__),"confidence":round(min(1,max(0,confidence)),2),"evidence":"optional framework adapter"})
            except Exception: pass
        if not local_frameworks and comp["languages"]: local_frameworks=[{"name":"Unknown","confidence":0.72,"evidence":"No known framework signature was found in this component"}]
        comp["frameworks"]=local_frameworks
    alltext="\n".join(contents.values())[:1_000_000]
    architecture=[]
    if entry: architecture.append({"pattern":"executable/CLI", "evidence":[x["file"] for x in entry[:20]]})
    if api: architecture.append({"pattern":"request/API handling", "evidence":[x["file"] for x in api[:20]]})
    if jobs: architecture.append({"pattern":"background/event processing", "evidence":[x["file"] for x in jobs[:20]]})
    if any(x in manifest_names for x in ("Dockerfile","Chart.yaml")) or any(Path(x).suffix==".tf" for x in contents): architecture.append({"pattern":"container/infrastructure deployment","evidence":[x for x in contents if Path(x).name.lower() in {"dockerfile","chart.yaml"} or x.endswith(".tf")][:30]})
    if not architecture: architecture.append({"pattern":"undetermined; structural evidence retained", "evidence":[]})
    symbol_by_name=defaultdict(list); symbols_by_file=defaultdict(list)
    for s in symbols:
        symbol_by_name[s["name"]].append(s); symbols_by_file[s["file"]].append(s)
        sid=f"{s['file']}::{s['name']}"
        relationships.append({"source":s["file"],"target":sid,"kind":"defines","line":s["line"]})
    call_pattern=re.compile(r"\b([A-Za-z_$][\w$]*)\s*\(")
    for rel,source in contents.items():
        definitions=sorted(symbols_by_file.get(rel,[]),key=lambda x:x["line"]); active=None; index=0
        for number,line in enumerate(source.splitlines(),1):
            while index<len(definitions) and definitions[index]["line"]<=number:
                active=definitions[index]; index+=1
            src=f"{active['file']}::{active['name']}" if active else rel
            for match in call_pattern.finditer(line):
                name=match.group(1); targets=symbol_by_name.get(name)
                if targets: relationships.append({"source":src,"target":f"{targets[0]['file']}::{name}","kind":"calls","line":number})
    test_files={t["file"] for t in tests}
    for testfile in test_files:
        tokens=set(re.findall(r"[A-Za-z_$][\w$]*",contents[testfile]))
        for name in tokens.intersection(symbol_by_name):
            for target in symbol_by_name[name]: relationships.append({"source":f"{target['file']}::{name}","target":testfile,"kind":"tested_by","line":0})
    graph_nodes=[{"id":f,"kind":"file"} for f in contents]+[{"id":f"{s['file']}::{s['name']}","name":s["name"],"kind":s["kind"],"file":s["file"],"line":s["line"]} for s in symbols]
    graph_nodes += [{"id":f"dependency::{d['ecosystem']}::{d['name']}","name":d["name"],"kind":"dependency"} for d in deps]
    graph_nodes += [{"id":f"endpoint::{e['file']}","kind":"possible_api_endpoint","file":e["file"]} for e in api]
    graph_nodes += [{"id":f"configuration::{e['file']}","kind":e["kind"],"file":e["file"]} for e in config]
    dependency_names={d["name"].lower().split("/")[-1]:d for d in deps}
    for edge in list(relationships):
        if edge["kind"]=="imports":
            imported=edge["target"].lower().split(".")[0].split("/")[-1]
            dep=dependency_names.get(imported)
            if dep:
                target=f"dependency::{dep['ecosystem']}::{dep['name']}"
                relationships.append({"source":edge["source"],"target":target,"kind":"depends_on","line":edge["line"]})
                relationships.append({"source":edge["source"],"target":target,"kind":"uses","line":edge["line"]})
    for endpoint in api: relationships.append({"source":endpoint["file"],"target":f"endpoint::{endpoint['file']}","kind":"routes_to","line":0})
    for file,source in contents.items():
        for number,line in enumerate(source.splitlines(),1):
            operation=re.search(r"(?i)\b(select|insert\s+into|update|delete\s+from)\b",line)
            if operation:
                kind="reads" if operation.group(1).lower()=="select" else "writes"
                node=f"database_operation::{file}:{number}"
                graph_nodes.append({"id":node,"kind":"database_operation","file":file,"line":number})
                relationships.append({"source":file,"target":node,"kind":kind,"line":number})
            hierarchy=re.search(r"(?i)\b(?:class|struct|interface)\s+([\w$]+)\s*(?:\(([^)]+)\)|extends\s+([\w$]+)|implements\s+([\w$, ]+))?",line)
            if hierarchy:
                child=hierarchy.group(1); child_nodes=symbol_by_name.get(child,[])
                for group,kind in ((hierarchy.group(2),"extends"),(hierarchy.group(3),"extends"),(hierarchy.group(4),"implements")):
                    if group:
                        for parent in re.findall(r"[A-Za-z_$][\w$]*",group):
                            if parent in symbol_by_name and child_nodes:
                                relationships.append({"source":f"{child_nodes[0]['file']}::{child}","target":f"{symbol_by_name[parent][0]['file']}::{parent}","kind":kind,"line":number})
    graph={"nodes":graph_nodes,"edges":relationships}
    test_map={"files":tests,"signals":sorted({"pytest" if "pytest" in alltext else "", "jest/vitest" if re.search(r"jest|vitest",alltext) else "", "go test" if any(x.endswith("_test.go") for x in contents) else "", "cargo test" if "Cargo.toml" in manifest_names else "", "phpunit" if "phpunit" in alltext.lower() else "", "maven/gradle test" if any(x in manifest_names for x in ("pom.xml","build.gradle","build.gradle.kts")) else "", "dotnet test" if any(x.endswith((".csproj",".sln")) for x in contents) else ""} - {""})}
    env_keys=set(re.findall(r"(?<!\w)(?:os\.environ(?:\.get)?\s*\[?\s*['\"]|process\.env\.)([A-Z][A-Z0-9_]{2,})",alltext))
    for rel,text in contents.items():
        if Path(rel).name.lower().startswith(".env"):
            env_keys.update(re.findall(r"(?m)^\s*([A-Z][A-Z0-9_]{2,})\s*=",text))
    config_map={"items":config,"environment_variables":sorted(env_keys)}
    manifest={"root":str(root),"file_count":len(files),"text_files_inspected":len(contents),"truncated":len(files)>=max_files or total_read>=max_total_bytes,"languages":langs,"frameworks":frameworks,"unknown_framework_supported":True,"framework_adapters_available":framework_adapters,"files":file_info,"dependencies":deps,"parser":"Tree-sitter syntax validation when grammar is available; generic symbol/import extraction otherwise"}
    return {"repository_manifest":manifest,"architecture":{"patterns":architecture},"code_graph":graph,"dependency_graph":{"dependencies":deps,"manifest_files":manifest_paths},"components":[{"name":k,**v} for k,v in components.items()],"entry_points":{"items":entry,"adapter_insights":[x.get("entry_points",[]) for x in adapter_results if x.get("entry_points")]},"configuration_map":config_map,"test_map":test_map,"signals":{"database":dbuse,"external_services":external,"api_endpoints":api,"authentication":auth,"authorization":[],"background_jobs":jobs},"adapter_insights":adapter_results,"symbols":symbols,"content":contents}

def write_discovery_artifacts(result: dict, destination: str | Path) -> None:
    dest=Path(destination); dest.mkdir(parents=True,exist_ok=True)
    for key in ("repository_manifest","architecture","code_graph","dependency_graph","components","entry_points","configuration_map","test_map"):
        (dest/f"{key}.json").write_text(json.dumps(result[key],indent=2),encoding="utf-8")
