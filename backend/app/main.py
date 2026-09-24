from __future__ import annotations
import json, os
import zipfile, shutil, uuid
from pathlib import PurePosixPath
from pathlib import Path
from fastapi import FastAPI, HTTPException, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from redis import Redis
from sqlalchemy import select
from .config import settings
from .db import Base, engine, SessionLocal
from .models import Repository, RepositoryComponent, Review, Finding, AgentRun, ToolRun, Analysis
from .review import RepositoryAgent

app=FastAPI(title="Universal Agentic Code Review",version="1.0.0",description="Repository-first, framework-agnostic code intelligence and review.")
app.add_middleware(CORSMiddleware,allow_origins=["*"],allow_methods=["*"],allow_headers=["*"])
@app.middleware("http")
async def optional_bearer_auth(request:Request,call_next):
    if settings.api_bearer_token and request.url.path.startswith("/api/") and request.url.path!="/api/health":
        from fastapi.responses import JSONResponse
        if request.headers.get("authorization")!=f"Bearer {settings.api_bearer_token}":
            return JSONResponse({"detail":"Unauthorized"},status_code=401)
    return await call_next(request)
class RepositoryCreate(BaseModel):
    name: str = Field(min_length=1,max_length=255)
    path: str = Field(min_length=1,max_length=2048,description="Repository directory under the mounted repository volume")
class ReviewCreate(BaseModel):
    mode: str = "full"
    question: str = ""
class ExplainRequest(BaseModel): question: str = Field(min_length=2,max_length=4000)

@app.on_event("startup")
def startup(): Base.metadata.create_all(bind=engine)

def _enqueue(job):
    try: Redis.from_url(settings.redis_url, socket_connect_timeout=1).rpush("review_jobs",json.dumps(job))
    except Exception as exc: raise HTTPException(503,"Job queue unavailable") from exc
def _repo_dict(r): return {"id":r.id,"name":r.name,"source":r.source,"path":r.path,"created_at":r.created_at.isoformat() if r.created_at else None,"manifest":r.manifest}

@app.get("/api/health")
def health(): return {"status":"ok","ai_configured":bool(settings.openai_api_key)}

@app.post("/api/repositories",status_code=201)
def add_repository(body:RepositoryCreate):
    root=Path(settings.repository_root).resolve(); path=(root/body.path).resolve()
    if root not in path.parents and path!=root: raise HTTPException(400,"Repository path must be inside the mounted repository volume")
    if not path.is_dir(): raise HTTPException(404,"Repository directory not found in repository volume")
    with SessionLocal() as db:
        repo=Repository(name=body.name,source=body.path,path=str(path)); db.add(repo); db.commit(); db.refresh(repo)
        return _repo_dict(repo)

@app.post("/api/repositories/upload",status_code=201)
async def upload_repository(name:str,archive:UploadFile=File(...)):
    if not archive.filename or not archive.filename.lower().endswith(".zip"):
        raise HTTPException(400,"Upload a ZIP archive")
    root=Path(settings.repository_root).resolve(); root.mkdir(parents=True,exist_ok=True)
    target=(root/str(uuid.uuid4())).resolve(); target.mkdir()
    archive_path=target.parent/(target.name+".zip"); total=0; entries=[]
    try:
        with archive_path.open("wb") as output:
            while chunk:=await archive.read(1024*1024):
                total+=len(chunk)
                if total>200*1024*1024: raise HTTPException(413,"Archive exceeds 200 MB limit")
                output.write(chunk)
        with zipfile.ZipFile(archive_path) as zf:
            infos=zf.infolist()
            if len(infos)>20000: raise HTTPException(413,"Archive has too many entries")
            expanded=sum(i.file_size for i in infos)
            if expanded>500*1024*1024: raise HTTPException(413,"Expanded archive exceeds 500 MB limit")
            safe_targets=[]
            for info in infos:
                p=PurePosixPath(info.filename)
                mode=(info.external_attr>>16)&0o170000
                if p.is_absolute() or ".." in p.parts or mode==0o120000 or info.flag_bits&1:
                    raise HTTPException(400,"Archive contains an unsafe path or symlink")
                destination=(target/Path(*p.parts)).resolve()
                if target not in destination.parents and destination!=target: raise HTTPException(400,"Archive path escapes repository root")
                safe_targets.append((info,destination))
            extracted=0
            for info,destination in safe_targets:
                if info.is_dir():
                    destination.mkdir(parents=True,exist_ok=True); continue
                destination.parent.mkdir(parents=True,exist_ok=True)
                with zf.open(info) as source, destination.open("xb") as output:
                    while chunk:=source.read(1024*1024):
                        extracted+=len(chunk)
                        if extracted>500*1024*1024: raise HTTPException(413,"Expanded archive exceeds 500 MB limit")
                        output.write(chunk)
        archive_path.unlink(missing_ok=True)
        # Zip archives commonly wrap the repository in one top-level folder.
        children=list(target.iterdir())
        repo_path=children[0] if len(children)==1 and children[0].is_dir() else target
        rel=repo_path.relative_to(root).as_posix()
        with SessionLocal() as db:
            repo=Repository(name=name[:255],source=f"upload:{archive.filename}",path=str(repo_path)); db.add(repo); db.commit(); db.refresh(repo)
            review=Review(repository_id=repo.id,mode="scan"); db.add(review); db.commit(); db.refresh(review)
            _enqueue({"type":"scan","repository_id":repo.id,"review_id":review.id})
            return {"repository":_repo_dict(repo),"review_id":review.id,"status":"queued","path":rel}
    except HTTPException:
        shutil.rmtree(target,ignore_errors=True); archive_path.unlink(missing_ok=True); raise
    except (zipfile.BadZipFile,OSError) as exc:
        shutil.rmtree(target,ignore_errors=True); archive_path.unlink(missing_ok=True)
        raise HTTPException(400,"Could not safely read ZIP archive") from exc

@app.get("/api/repositories")
def list_repositories():
    with SessionLocal() as db: return [_repo_dict(r) for r in db.scalars(select(Repository).order_by(Repository.created_at.desc())).all()]

@app.get("/api/repositories/{repository_id}")
def get_repository(repository_id:str):
    with SessionLocal() as db:
        r=db.get(Repository,repository_id)
        if not r: raise HTTPException(404,"Repository not found")
        return _repo_dict(r)

@app.post("/api/repositories/{repository_id}/scan",status_code=202)
def scan_repository(repository_id:str):
    with SessionLocal() as db:
        repo=db.get(Repository,repository_id)
        if not repo: raise HTTPException(404,"Repository not found")
        review=Review(repository_id=repo.id,mode="scan"); db.add(review); db.commit(); db.refresh(review)
        _enqueue({"type":"scan","repository_id":repo.id,"review_id":review.id})
        return {"review_id":review.id,"status":"queued"}

@app.post("/api/repositories/{repository_id}/review",status_code=202)
def create_review(repository_id:str,body:ReviewCreate):
    if body.mode not in {"full","pr","file","function","security","architecture","bug"}: raise HTTPException(400,"Unsupported review mode")
    with SessionLocal() as db:
        repo=db.get(Repository,repository_id)
        if not repo: raise HTTPException(404,"Repository not found")
        review=Review(repository_id=repo.id,mode=body.mode); db.add(review); db.commit(); db.refresh(review)
        _enqueue({"type":"review","repository_id":repo.id,"review_id":review.id,"mode":body.mode,"question":body.question})
        return {"review_id":review.id,"status":"queued"}

@app.get("/api/repositories/{repository_id}/reviews")
def repository_reviews(repository_id:str):
    with SessionLocal() as db:
        if not db.get(Repository,repository_id): raise HTTPException(404,"Repository not found")
        rows=db.scalars(select(Review).where(Review.repository_id==repository_id).order_by(Review.created_at.desc())).all()
        return [{"id":r.id,"mode":r.mode,"status":r.status,"summary":r.summary,"created_at":r.created_at.isoformat() if r.created_at else None,"findings_count":len(db.scalars(select(Finding).where(Finding.review_id==r.id)).all())} for r in rows]

def _explain(repository_id,question):
    with SessionLocal() as db:
        repo=db.get(Repository,repository_id)
        if not repo: raise HTTPException(404,"Repository not found")
        if not repo.manifest:
            data=RepositoryAgent().run(repo); db.commit()
        else: data=repo.manifest
        answer="Repository evidence has been discovered. Configure OPENAI_API_KEY to ask natural-language questions."
        evidence={"languages":data.get("repository_manifest",{}).get("languages",[]),"frameworks":data.get("repository_manifest",{}).get("frameworks",[]),"architecture":data.get("architecture",{}).get("patterns",[])}
        if settings.openai_api_key:
            from .review import _ai_review
            output=_ai_review(repo,"explain",data, __import__(".discovery",fromlist=["discover_repository"]).discover_repository(repo.path)["content"],question)
            if output: answer=output.summary
        db.add(Analysis(repository_id=repo.id,kind="chat",payload={"question":question,"answer":answer,"evidence":evidence})); db.commit()
        return {"answer":answer,"evidence":evidence}

@app.post("/api/repositories/{repository_id}/explain")
def explain(repository_id:str,body:ExplainRequest): return _explain(repository_id,body.question)
@app.post("/api/repositories/{repository_id}/chat")
def chat(repository_id:str,body:ExplainRequest): return _explain(repository_id,body.question)

@app.get("/api/repositories/{repository_id}/architecture")
def architecture(repository_id:str):
    with SessionLocal() as db:
        repo=db.get(Repository,repository_id)
        if not repo: raise HTTPException(404,"Repository not found")
        return repo.manifest.get("architecture",{}) if repo.manifest else {"status":"not_scanned"}
@app.get("/api/repositories/{repository_id}/graph")
def graph(repository_id:str):
    with SessionLocal() as db:
        repo=db.get(Repository,repository_id)
        if not repo: raise HTTPException(404,"Repository not found")
        return repo.manifest.get("code_graph",{}) if repo.manifest else {"status":"not_scanned"}
@app.get("/api/reviews/{review_id}")
def get_review(review_id:str):
    with SessionLocal() as db:
        r=db.get(Review,review_id)
        if not r: raise HTTPException(404,"Review not found")
        return {"id":r.id,"repository_id":r.repository_id,"mode":r.mode,"status":r.status,"summary":r.summary,"created_at":r.created_at.isoformat() if r.created_at else None}
@app.get("/api/reviews/{review_id}/findings")
def findings(review_id:str):
    with SessionLocal() as db:
        if not db.get(Review,review_id): raise HTTPException(404,"Review not found")
        return [{"id":f.id,"file":f.file,"line":f.line,"symbol":f.symbol,"severity":f.severity,"certainty":f.certainty,"problem":f.problem,"root_cause":f.root_cause,"evidence":f.evidence,"current_code":f.current_code,"recommended_code":f.recommended_code,"recommended_change":f.recommended_change,"tests_required":f.tests_required,"why_here":f.why_here,"related_files":f.related_files,"affected_callers":f.affected_callers,"impact":f.impact,"confidence":f.confidence,"patch":f.patch} for f in db.scalars(select(Finding).where(Finding.review_id==review_id)).all()]
@app.get("/api/reviews/{review_id}/activity")
def activity(review_id:str):
    with SessionLocal() as db:
        if not db.get(Review,review_id): raise HTTPException(404,"Review not found")
        agents=db.scalars(select(AgentRun).where(AgentRun.review_id==review_id)).all(); tools=db.scalars(select(ToolRun).where(ToolRun.review_id==review_id)).all()
        return {"agents":[{"agent":a.agent,"status":a.status,"summary":a.summary,"metrics":a.metrics} for a in agents],"tools":[{"tool":t.tool,"status":t.status,"output":t.output} for t in tools]}
@app.post("/api/reviews/{review_id}/patch")
def patch_preview(review_id:str):
    with SessionLocal() as db:
        if not db.get(Review,review_id): raise HTTPException(404,"Review not found")
        return [{"finding_id":f.id,"file":f.file,"diff":f.patch,"explanation":f.recommended_change} for f in db.scalars(select(Finding).where(Finding.review_id==review_id,Finding.patch!="")).all()]
