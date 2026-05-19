"""配置管理模块"""
import os
from pathlib import Path
from pydantic_settings import BaseSettings
from pydantic import Field

PROJECT_ROOT = Path(__file__).parent.parent.parent
USER_CONFIG_DIR = Path(os.environ.get("JIANLAI_HOME", Path.home() / ".jianlai")).expanduser()
USER_ENV_FILE = USER_CONFIG_DIR / ".env"
PROJECT_ENV_FILE = PROJECT_ROOT / ".env"


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

    # 配置优先级：
    # 1. 真实环境变量（pydantic-settings 默认最高）
    # 2. 用户级配置 ~/.jianlai/.env（适合全局安装后任意目录启动）
    # 3. 项目根目录 .env（适合源码开发）
    model_config = {
        "env_file": (str(PROJECT_ENV_FILE), str(USER_ENV_FILE)),
        "env_file_encoding": "utf-8",
    }

    @property
    def db_full_path(self) -> Path:
        p = Path(self.database_path).expanduser()
        if not p.is_absolute():
            p = PROJECT_ROOT / p
        p.parent.mkdir(parents=True, exist_ok=True)
        return p


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
