# Atlas — Universal Agentic Code Review

Atlas discovers a repository before attempting a review. The core pipeline is language and framework agnostic: it inventories manifests and source files, infers languages/framework signatures, maps components and entry points, extracts portable symbols/imports, records configuration/testing/infrastructure signals, and then selects generic review capabilities. Optional framework adapters can enhance that inventory without being required.

## Start

1. Install Docker Desktop with Compose.
2. Copy `.env.example` to `.env` and set `OPENAI_API_KEY` for contextual AI review. Without a key, discovery and generic static checks still work.
3. Put repository folders under the Compose `repositories` volume. For a simple local workflow, create a folder beside this project and bind-mount it by adding `./repositories:/data/repositories` to the `backend` and `worker` volume lists. Do not mount untrusted source over application files.
4. Run `docker compose up --build` and open [http://localhost:3000](http://localhost:3000).
5. Upload a repository ZIP in the dashboard or register a path relative to `/data/repositories`, then start a scan or review.

The included acceptance fixtures live in `samples/` (Python, TypeScript, PHP, Java, Go, and a mixed-language monorepo). To expose them, mount `./samples:/data/repositories:ro` on both `backend` and `worker`, then register the fixture directory by name.

## Services and data

- `backend`: JSON API on port 8000; `/docs` exposes the OpenAPI schema.
- `worker`: Redis-backed asynchronous discovery and review jobs.
- `frontend`: technology-neutral dashboard on port 3000.
- `postgres`: generic repository, component, review, finding, graph, analysis, patch, agent-run, and tool-run records.
- `redis`: job queue.
- `sandbox`: isolated, non-root service with no network, dropped Linux capabilities, read-only filesystem, and resource limits. Arbitrary repository commands/tests are intentionally not launched automatically.

Repository and report artifacts persist in Docker volumes named `repositories` and `reports`; Postgres and Redis use separate named volumes. The scanner does not follow symlinks, does not read common generated/dependency directories, caps file size/count, and never executes repository code. It emits `repository_manifest.json`, `architecture.json`, `code_graph.json`, `dependency_graph.json`, `components.json`, `entry_points.json`, `configuration_map.json`, and `test_map.json` for each scan under the reports volume.

## API

The requested endpoints are implemented under `/api`: repository create/list/detail/scan/review/explain/chat/architecture/graph; review detail/findings/activity/patch preview; and health. Repository creation accepts only a directory inside the mounted repository volume. The patch route returns a preview and never changes repository files.

## Extension points

`ParserInterface`, `LanguageParser`, `LanguageDetector`, `FrameworkDetector`, `FrameworkAdapter`, and `UniversalOrchestrator` form the extension boundaries. Generic symbol extraction and repository evidence remain available when Tree-sitter has no grammar or no framework adapter matches. Adapters can be added to `backend/app/framework_adapters/` and are optional.

## Operational notes

Set `OPENAI_API_KEY` and `OPENAI_MODEL` to enable model-assisted explanations/reviews. Optionally set `API_BEARER_TOKEN`; the UI settings control stores the token in local browser storage. Only a bounded set of relevant source context is sent to the model; repository text is explicitly treated as untrusted input, model output is validated through Pydantic, and malformed JSON receives one retry. The UI activity view reports action summaries and counts, not private chain-of-thought.

Before exposing this single-workspace starter to a network, add identity/access control, TLS via a trusted reverse proxy, managed secrets and backups, per-tenant isolation, queue retry/dead-letter handling, migration management, and resource quotas. Compose's sample Postgres credentials and open API are for local evaluation only. This baseline is designed to be extended for production operations; it is not a hardened multi-tenant SaaS deployment.
