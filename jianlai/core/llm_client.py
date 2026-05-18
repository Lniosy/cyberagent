"""DeepSeek LLM 客户端，兼容 OpenAI SDK

集成 token 统计和成本追踪（参考 pi 的 SessionStats 设计）
"""
from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Any

from openai import AsyncOpenAI, APIStatusError, APITimeoutError, APIConnectionError

from jianlai.core.config import get_settings

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

# DeepSeek 定价（每百万 token，单位 USD）
# 参考 https://api-docs.deepseek.com/quick_start/pricing
DEEPSEEK_PRICING = {
    "deepseek-v4-pro": {"input": 0.27, "output": 1.10},
    "deepseek-v4-flash": {"input": 0.07, "output": 0.28},
}


@dataclass
class TokenStats:
    """Token 统计"""
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    cost_usd: float = 0.0
    call_count: int = 0


@dataclass
class SessionStats:
    """会话统计 — 追踪所有 LLM 调用的成本"""
    pro: TokenStats = field(default_factory=TokenStats)
    flash: TokenStats = field(default_factory=TokenStats)

    @property
    def total_cost(self) -> float:
        return self.pro.cost_usd + self.flash.cost_usd

    @property
    def total_calls(self) -> int:
        return self.pro.call_count + self.flash.call_count

    @property
    def total_tokens(self) -> int:
        return self.pro.total_tokens + self.flash.total_tokens

    def record(self, model: str, input_tokens: int, output_tokens: int):
        """记录一次 LLM 调用的 token 用量"""
        total = input_tokens + output_tokens
        pricing = DEEPSEEK_PRICING.get(model, {"input": 0.27, "output": 1.10})
        cost = (input_tokens * pricing["input"] + output_tokens * pricing["output"]) / 1_000_000

        if "flash" in model:
            target = self.flash
        else:
            target = self.pro

        target.input_tokens += input_tokens
        target.output_tokens += output_tokens
        target.total_tokens += total
        target.cost_usd += cost
        target.call_count += 1

        logger.info(
            "[cost] %s: %d in + %d out = $%.4f (累计: $%.4f, %d calls, %d tokens)",
            model, input_tokens, output_tokens, cost,
            self.total_cost, self.total_calls, self.total_tokens,
        )

    def summary(self) -> dict[str, Any]:
        return {
            "pro": {
                "calls": self.pro.call_count,
                "input_tokens": self.pro.input_tokens,
                "output_tokens": self.pro.output_tokens,
                "cost_usd": round(self.pro.cost_usd, 4),
            },
            "flash": {
                "calls": self.flash.call_count,
                "input_tokens": self.flash.input_tokens,
                "output_tokens": self.flash.output_tokens,
                "cost_usd": round(self.flash.cost_usd, 4),
            },
            "total": {
                "calls": self.total_calls,
                "tokens": self.total_tokens,
                "cost_usd": round(self.total_cost, 4),
            },
        }


class LLMClient:
    """封装 DeepSeek API 调用，集成 token 统计"""

    def __init__(self):
        settings = get_settings()
        self._client = AsyncOpenAI(
            api_key=settings.deepseek_api_key,
            base_url=settings.deepseek_base_url,
        )
        self._pro_model = settings.deepseek_pro_model
        self._flash_model = settings.deepseek_flash_model
        self.stats = SessionStats()

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

    async def chat_with_tools(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        model: str | None = None,
    ) -> str:
        """带 function calling 的 LLM 调用（Agent Loop 专用）"""
        use_model = model or self._pro_model
        logger.debug("LLM tool call: model=%s, messages=%d, tools=%d",
                      use_model, len(messages), len(tools) if tools else 0)

        kwargs: dict[str, Any] = {
            "model": use_model,
            "messages": messages,
            "temperature": 0.1,
            "timeout": 120,
        }
        if tools:
            kwargs["tools"] = tools

        last_error = None
        for attempt in range(3):
            try:
                response = await self._client.chat.completions.create(**kwargs)
                msg = response.choices[0].message

                # Token 统计
                usage = response.usage
                if usage:
                    self.stats.record(
                        use_model,
                        usage.prompt_tokens or 0,
                        usage.completion_tokens or 0,
                    )

                # 构建响应（含 tool_calls）
                result: dict[str, Any] = {"role": "assistant"}
                if msg.content:
                    result["content"] = msg.content
                if msg.tool_calls:
                    result["tool_calls"] = [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments,
                            },
                        }
                        for tc in msg.tool_calls
                    ]

                return json.dumps(result, ensure_ascii=False)

            except (APITimeoutError, APIConnectionError) as e:
                last_error = e
                wait = 2 ** attempt
                logger.warning("[LLM] 重试 %d/3, %ds: %s", attempt + 1, wait, e)
                await asyncio.sleep(wait)
            except APIStatusError as e:
                if e.status_code in (429, 500, 502, 503):
                    last_error = e
                    await asyncio.sleep(2 ** attempt)
                else:
                    raise

        raise last_error  # type: ignore

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
        max_retries: int = 3,
    ) -> str:
        logger.debug("LLM call: model=%s, prompt_len=%d", model, len(user_prompt))

        last_error = None
        for attempt in range(max_retries):
            try:
                response = await self._client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    temperature=temperature,
                    timeout=60,
                )
                content = response.choices[0].message.content or ""

                # Token 统计
                usage = response.usage
                if usage:
                    self.stats.record(
                        model,
                        usage.prompt_tokens or 0,
                        usage.completion_tokens or 0,
                    )

                logger.debug("LLM response len=%d", len(content))
                return content

            except (APITimeoutError, APIConnectionError) as e:
                last_error = e
                wait = 2 ** attempt
                logger.warning("[LLM] 连接/超时错误 (attempt %d/%d), %ds后重试: %s",
                               attempt + 1, max_retries, wait, e)
                await asyncio.sleep(wait)

            except APIStatusError as e:
                last_error = e
                if e.status_code in (429, 500, 502, 503):
                    wait = 2 ** attempt * (2 if e.status_code == 429 else 1)
                    logger.warning("[LLM] HTTP %d (attempt %d/%d), %ds后重试",
                                   e.status_code, attempt + 1, max_retries, wait)
                    await asyncio.sleep(wait)
                else:
                    raise

            except Exception as e:
                logger.error("[LLM] 不可恢复错误: %s", e)
                raise

        logger.error("[LLM] %d 次重试全部失败", max_retries)
        raise last_error

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
