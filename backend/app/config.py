from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    database_url: str = "sqlite:///./review.db"
    redis_url: str = "redis://localhost:6379/0"
    repository_root: str = "./repositories"
    report_root: str = "./reports"
    openai_api_key: str | None = None
    openai_model: str = "gpt-5.5"
    api_bearer_token: str | None = None
    max_file_bytes: int = 1_000_000
    max_files: int = 20_000
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
