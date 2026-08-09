"""Runtime settings loaded without exposing secret values."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

SSH_ALIAS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
REMOTE_ROOT_RE = re.compile(r"^(?:~|/)[A-Za-z0-9._/-]+$")


@dataclass(frozen=True, slots=True)
class Settings:
    data_dir: Path
    ssh_alias: str
    remote_root: str
    llm_base_url: str | None
    llm_api_key: str | None
    llm_model: str | None
    language: str

    @classmethod
    def from_env(cls, *, load_local_env: bool = True) -> Settings:
        if load_local_env:
            load_dotenv(override=False)
        data_dir = Path(os.getenv("AEGISSCOPE_DATA_DIR", "./var")).expanduser().resolve()
        ssh_alias = os.getenv("AEGISSCOPE_SSH_ALIAS", "kali-src").strip()
        remote_root = os.getenv("AEGISSCOPE_REMOTE_ROOT", "~/src-runner").strip().rstrip("/")
        language = os.getenv("AEGISSCOPE_LANGUAGE", "zh-CN").strip()
        if not SSH_ALIAS_RE.fullmatch(ssh_alias):
            raise ValueError("AEGISSCOPE_SSH_ALIAS contains unsafe characters")
        if not REMOTE_ROOT_RE.fullmatch(remote_root) or ".." in remote_root.split("/"):
            raise ValueError("AEGISSCOPE_REMOTE_ROOT must be a safe absolute or home path")
        if language not in {"zh-CN", "en"}:
            raise ValueError("AEGISSCOPE_LANGUAGE must be zh-CN or en")
        return cls(
            data_dir=data_dir,
            ssh_alias=ssh_alias,
            remote_root=remote_root,
            llm_base_url=os.getenv("AEGISSCOPE_LLM_BASE_URL") or None,
            llm_api_key=os.getenv("AEGISSCOPE_LLM_API_KEY") or None,
            llm_model=os.getenv("AEGISSCOPE_LLM_MODEL") or None,
            language=language,
        )

    def ensure_local_directories(self) -> None:
        for relative in (
            "db",
            "jobs",
            "proposals",
            "evidence",
            "reports",
            "imports",
            "traffic-analyses",
            "campaigns",
        ):
            (self.data_dir / relative).mkdir(parents=True, exist_ok=True)
