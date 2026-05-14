"""DeepSeek LLM 客户端，兼容 OpenAI SDK"""
from __future__ import annotations

import json
import logging
from typing import Any

from openai import AsyncOpenAI

from cyberagent.core.config import get_settings

logger = logging.getLogger(__name__)

SYSTEM_PROMPT_RECON = """你是一个专业的网络安全侦察分析专家。你的任务是分析目标域名的侦察数据，识别潜在的安全问题和攻击面。

分析时关注：
1. 技术栈识别 — 框架、CMS、服务器版本，已知CVE
2. 暴露面分析 — 不该公开的端口、管理后台、API端点
3. 配置问题 — 默认配置、信息泄露、缺失安全头
4. 攻击向量 — 基于发现，建议下一步测试方向

输出格式要求：JSON，结构如下：
{
  "summary": "简要总结",
  "tech_stack": [{"name": "技术名", "version": "版本", "cve_list": []}],
  "attack_surface": [{"type": "类型", "detail": "详情", "risk": "high/medium/low"}],
  "suggested_next_steps": ["建议的下一步操作"]
}"""


class LLMClient:
    """封装 DeepSeek API 调用"""

    def __init__(self):
        settings = get_settings()
        self._client = AsyncOpenAI(
            api_key=settings.deepseek_api_key,
            base_url=settings.deepseek_base_url,
        )
        self._pro_model = settings.deepseek_pro_model
        self._flash_model = settings.deepseek_flash_model

    async def chat_pro(
        self,
        user_prompt: str,
        system_prompt: str = SYSTEM_PROMPT_RECON,
        temperature: float = 0.1,
    ) -> str:
        """使用 V4 Pro 模型进行复杂推理"""
        return await self._call(self._pro_model, user_prompt, system_prompt, temperature)

    async def chat_flash(
        self,
        user_prompt: str,
        system_prompt: str = "你是一个安全分析助手。简洁准确地回答问题。",
        temperature: float = 0.1,
    ) -> str:
        """使用 Flash 模型进行简单任务"""
        return await self._call(self._flash_model, user_prompt, system_prompt, temperature)

    async def chat_json_pro(
        self,
        user_prompt: str,
        system_prompt: str = SYSTEM_PROMPT_RECON,
    ) -> dict[str, Any]:
        """调用 Pro 模型并解析 JSON 响应"""
        raw = await self.chat_pro(user_prompt, system_prompt)
        return self._parse_json(raw)

    async def _call(
        self,
        model: str,
        user_prompt: str,
        system_prompt: str,
        temperature: float,
    ) -> str:
        logger.debug("LLM call: model=%s, prompt_len=%d", model, len(user_prompt))
        response = await self._client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=temperature,
        )
        content = response.choices[0].message.content or ""
        logger.debug("LLM response len=%d", len(content))
        return content

    @staticmethod
    def _parse_json(text: str) -> dict[str, Any]:
        """从 LLM 响应中提取 JSON"""
        text = text.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            lines = [l for l in lines if not l.strip().startswith("```")]
            text = "\n".join(lines)
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            start = text.find("{")
            end = text.rfind("}") + 1
            if start != -1 and end > start:
                return json.loads(text[start:end])
            raise
