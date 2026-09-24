"""Read-only, framework-neutral repository inspection tools."""
from pathlib import Path
import re, subprocess
from .discovery import discover_repository

def _root(root): return Path(root).resolve()
def _safe(root,path):
    base=_root(root); target=(base/path).resolve()
    if target!=base and base not in target.parents: raise ValueError("path is outside repository")
    if target.is_symlink(): raise ValueError("symlinks are not inspected")
    return target
def read_file(root, path): return _safe(root,path).read_text(encoding="utf-8",errors="replace")
def read_lines(root,path,start,end): return "\n".join(read_file(root,path).splitlines()[max(0,start-1):max(start-1,end)])
def list_directory(root,path="."): return sorted(p.name for p in _safe(root,path).iterdir() if not p.is_symlink())
def search_code(root,query,case_sensitive=False):
    flags=0 if case_sensitive else re.I
    try: pattern=re.compile(query,flags)
    except re.error: pattern=re.compile(re.escape(query),flags)
    output=[]
    for rel,text in discover_repository(root)["content"].items():
        for n,line in enumerate(text.splitlines(),1):
            if pattern.search(line): output.append({"file":rel,"line":n,"text":line[:500]})
    return output
def find_symbol(root,name):
    d=discover_repository(root); return [x for x in d["symbols"] if x["name"]==name]
def find_definition(root,name): return find_symbol(root,name)
def find_references(root,name): return search_code(root,rf"\b{re.escape(name)}\b")
def find_callers(root,name):
    d=discover_repository(root)
    return [e for e in d["code_graph"]["edges"] if e["kind"]=="calls" and e["target"].endswith("::"+name)]
def find_callees(root,file):
    text=read_file(root,file); return sorted(set(re.findall(r"\b([A-Za-z_$][\w$]*)\s*\(",text)))
def find_imports(root,file): return [e for e in discover_repository(root)["code_graph"]["edges"] if e["source"]==file and e["kind"]=="imports"]
def find_exports(root,file):
    text=read_file(root,file); return [{"name":m.group(1),"line":text[:m.start()].count("\n")+1} for m in re.finditer(r"(?m)^\s*export\s+(?:default\s+)?(?:function|class|const|let|var)?\s*([\w$]+)",text)]
def find_tests(root,symbol=None):
    d=discover_repository(root); tests=d["test_map"]["files"]
    if not symbol: return tests
    return [t for t in tests if symbol.lower() in t["file"].lower() or symbol.lower() in read_file(root,t["file"]).lower()]
def get_git_diff(root,base="HEAD"): return _git(root,["diff","--no-ext-diff","--unified=3",base,"--"])
def get_git_history(root,path=None,limit=30): return _git(root,["log","--no-ext-diff",f"-n{max(1,min(limit,100))}","--format=%h %ad %s","--date=short","--",*([path] if path else [])])
def _git(root,args):
    try: return subprocess.run(["git","-C",str(_root(root)),*args],capture_output=True,text=True,timeout=10,check=False).stdout
    except (OSError,subprocess.TimeoutExpired): return ""
def inspect_dependencies(root): return discover_repository(root)["dependency_graph"]
def detect_entry_points(root): return discover_repository(root)["entry_points"]
def detect_configuration(root): return discover_repository(root)["configuration_map"]
def detect_database_usage(root): return discover_repository(root)["signals"]["database"]
def detect_external_services(root): return discover_repository(root)["signals"]["external_services"]
def detect_api_endpoints(root): return discover_repository(root)["signals"]["api_endpoints"]
def detect_authentication(root): return discover_repository(root)["signals"]["authentication"]
def detect_authorization(root): return search_code(root,r"(?i)(authorize|permission|role_required|has_permission|access.?control)")
def detect_background_jobs(root): return discover_repository(root)["signals"]["background_jobs"]
def detect_environment_variables(root): return discover_repository(root)["configuration_map"]["environment_variables"]
