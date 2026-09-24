import json, time
from redis import Redis
from sqlalchemy import select
from .config import settings
from .db import Base,engine,SessionLocal
from .models import Repository, Review, RepositoryComponent, Analysis, CodeSymbol, CodeRelationship
from .review import RepositoryAgent, run_review

def _scan(db,repo,review):
    data=RepositoryAgent().run(repo)
    db.query(RepositoryComponent).filter_by(repository_id=repo.id).delete()
    db.query(CodeSymbol).filter_by(repository_id=repo.id).delete()
    db.query(CodeRelationship).filter_by(repository_id=repo.id).delete()
    for c in data["components"]: db.add(RepositoryComponent(repository_id=repo.id,name=c["name"],root=c["name"],languages=c["languages"],frameworks=c["frameworks"]))
    for s in data["symbols"]: db.add(CodeSymbol(repository_id=repo.id,name=s["name"],kind=s["kind"],file=s["file"],line=s["line"],language=s["language"]))
    for e in data["code_graph"]["edges"]: db.add(CodeRelationship(repository_id=repo.id,source=e["source"],target=e["target"],kind=e["kind"],file=e["source"],line=e["line"]))
    db.add(Analysis(repository_id=repo.id,kind="discovery",payload={k:v for k,v in data.items() if k not in {"content","symbols"}}))
    review.status="completed"; review.summary=f"Discovered {data['repository_manifest']['text_files_inspected']} text files across {len(data['repository_manifest']['languages'])} languages; identified {len(data['repository_manifest']['frameworks'])} framework signatures."
    db.commit()

def main():
    Base.metadata.create_all(bind=engine)
    redis=Redis.from_url(settings.redis_url)
    while True:
        try:
            item=redis.blpop("review_jobs",timeout=5)
            if not item: continue
            job=json.loads(item[1])
            with SessionLocal() as db:
                repo=db.get(Repository,job["repository_id"]); review=db.get(Review,job["review_id"])
                if not repo or not review: continue
                if job["type"]=="scan": _scan(db,repo,review)
                elif job["type"]=="review":
                    if not repo.manifest: _scan(db,repo,review)
                    run_review(db,repo,review,job.get("mode","full"),job.get("question",""))
        except Exception as exc:
            print(f"worker recovered from {type(exc).__name__}",flush=True); time.sleep(2)
if __name__=="__main__": main()
