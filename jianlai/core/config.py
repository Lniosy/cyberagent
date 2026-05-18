"""配置管理模块"""
import os
from pathlib import Path
from pydantic_settings import BaseSettings
from pydantic import Field

PROJECT_ROOT = Path(__file__).parent.parent.parent


class Settings(BaseSettings):
    # DeepSeek API
    deepseek_api_key: str = Field(default="")
    deepseek_base_url: str = Field(default="https://api.deepseek.com")
    deepseek_pro_model: str = Field(default="deepseek-v4-pro")
    deepseek_flash_model: str = Field(default="deepseek-v4-flash")

    # 数据库
    database_path: str = Field(default="data/jianlai.db")

    # 并发
    max_concurrent_tasks: int = Field(default=5)

    # 日志
    log_level: str = Field(default="INFO")

    model_config = {"env_file": str(PROJECT_ROOT / ".env"), "env_file_encoding": "utf-8"}

    @property
    def db_full_path(self) -> Path:
        p = PROJECT_ROOT / self.database_path
        p.parent.mkdir(parents=True, exist_ok=True)
        return p


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
