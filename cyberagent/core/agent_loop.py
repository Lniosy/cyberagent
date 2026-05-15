"""自主 Agent 循环 — ReAct 模式，对齐 pi 的 runLoop

核心设计（参考 pi packages/agent/src/agent-loop.ts）：
- 双层 while 循环：外层处理 follow-up，内层处理 tool call + steering
- LLM 自主决定调用哪个工具（不是固定流程）
- 工具结果反馈到 context，影响下一轮决策
- 错误恢复：错误编码进 context，LLM 自主决定下一步
- 终止条件：任务完成 / max_turns / abort
- Steering 队列：用户可实时注入指令

无人值守模式：
- Agent 持续运行直到 LLM 判断任务完成
- 遇到错误不放弃，将错误信息反馈给 LLM
- LLM 自主决定重试、换策略、跳过或降级
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from cyberagent.core.llm_client import LLMClient
from cyberagent.core.session import SessionManager
from cyberagent.core.compaction import ContextCompressor
from cyberagent.core.tools import ToolRegistry, ToolResult
from cyberagent.core.skill_loader import SkillLoader
from cyberagent.core.safety import get_safety_checker

logger = logging.getLogger(__name__)

# 系统 prompt — 定义 Agent 的身份和行为（行动导向，防止分析循环）
AGENT_SYSTEM_PROMPT = """你是一个专业的网络安全自动化渗透测试 Agent。

## 核心原则：行动优先
你的任务是**执行测试**，不是反复分析。每一轮你必须调用至少一个测试工具。
绝对不要连续两轮只调用 get_findings_summary 或 analyze_findings。

## 可用工具
侦察：subdomain_enum, port_scan, http_probe, api_enum, js_analyze
扫描：test_sqli, test_xss, test_idor, test_graphql, test_cors, test_headers
情报：cve_query, poc_search, load_skill
分析：analyze_findings, get_findings_summary
报告：generate_report, complete_task

## 执行规则（必须遵守）
1. **每轮必须行动**：调用至少一个侦察/扫描/情报工具，不要只分析不测试
2. **侦察完成后立即测试**：有 API 端点就测 IDOR/SQLi，有参数就测 XSS
3. **不重复相同操作**：同一个工具对同一个目标只调用一次
4. **不放弃任务**：失败时换工具或换目标，不要停下来
5. **已知端口直接用**：初始上下文有端口信息就直接探测，不扫描全端口
6. **完成标准**：测试了至少 3 种漏洞类型后，系统会提示你调用 generate_report 和 complete_task，收到提示后立即执行

## 安全红线（不可违反）
- 只用 GET/HEAD/OPTIONS 和受控 POST
- 禁止增删改操作、DDoS、数据窃取
- PoC 必须安全审核
3. 使用 load_skill 加载对应漏洞类型的详细知识（省 token，按需加载）
4. 并行执行多个独立测试
5. 分析结果，决定下一步
6. 重复 2-5 直到测试充分
7. 生成最终报告
8. 调用 complete_task 结束

## Skill 知识库
你有一个按需加载的安全知识库，包含 100+ 种漏洞类型的详细测试方法。
使用 load_skill(vuln_type="xxx") 加载对应知识，获得：
- 针对性 payload（比内置的更全面）
- 绕过技巧（WAF 绕过、编码变换）
- 真实 CVE 场景
- 检测方法和验证步骤

可用的 skill 类型：sqli, xss, ssrf, idor, csrf, xxe, ssti, nosqli, graphql, jwt, cors,
upload, cmd_injection, dir_traversal, open_redirect, race_condition, request_smuggling,
prototype_pollution, subdomain_takeover, waf_bypass, auth_bypass, api_sec

## 重要
- 每次回复时，说明你的思考过程和下一步计划
- 如果某个测试失败，说明原因并尝试替代方案
- 优先测试高危漏洞（SQLi、RCE、IDOR）
- 生成的 payload 必须是安全的（只读探测，不执行破坏操作）"""


@dataclass
class AgentLoopConfig:
    """Agent 循环配置"""
    max_turns: int = 50            # 最大轮次（防无限循环）
    max_time: int = 1800           # 最大运行时间（30分钟）
    auto_mode: bool = True         # 无人值守模式（无 steering 时继续运行）
    compaction_enabled: bool = True  # 是否启用上下文压缩


class AgentLoop:
    """自主 Agent 循环

    对齐 pi 的 runLoop() 设计：
    - 双层 while（外层 follow-up，内层 tool call + steering）
    - LLM 自主决策 + 工具执行 + 结果反馈
    - 错误恢复 + 终止条件 + Steering
    """

    def __init__(
        self,
        llm: LLMClient,
        tools: ToolRegistry,
        session: SessionManager,
        compressor: ContextCompressor | None = None,
        config: AgentLoopConfig | None = None,
        skill_loader: SkillLoader | None = None,
        knowledge: Any | None = None,
    ):
        self.llm = llm
        self.tools = tools
        self.session = session
        self.compressor = compressor
        self.config = config or AgentLoopConfig()
        self.skill_loader = skill_loader or SkillLoader()
        self.knowledge = knowledge  # KnowledgeBase 实例

        self._steering_queue: asyncio.Queue[str] = asyncio.Queue()
        self._followup_queue: asyncio.Queue[str] = asyncio.Queue()
        self._turn_count: int = 0
        self._start_time: float = 0
        self._abort: bool = False
        self._task_complete: bool = False

    # ---- 公共接口 ----

    async def run(self, target: str, initial_context: str = "") -> dict[str, Any]:
        """启动 Agent 循环（对齐 pi runLoop）

        Args:
            target: 测试目标（域名或URL）
            initial_context: 初始上下文（侦察结果等）

        Returns:
            最终结果（包含 findings、report、stats）
        """
        self._start_time = time.time()
        self._turn_count = 0
        self._target = target  # 保存目标域名供后续使用
        self._recent_tools: list[str] = []  # 最近调用的工具名（卡住检测用）
        self._tested_pairs: set[str] = set()  # 已测试的 (tool:url) 去重
        self._tested_vuln_types: set[str] = set()  # 已测试的漏洞类型
        self._report_generated: bool = False  # 报告是否已生成

        # 注入系统 prompt
        self.session.append(
            role="system",
            content=AGENT_SYSTEM_PROMPT,
            metadata={"type": "system_prompt"},
        )

        # 加载历史知识（如果知识库可用）
        knowledge_context = ""
        if self.knowledge:
            try:
                strategy = await self.knowledge.optimize_strategy(
                    self.llm, target, tech_stack=[],
                )
                if strategy:
                    knowledge_context = (
                        f"\n\n## 历史经验（基于过往扫描）:\n"
                        f"- 优先测试: {strategy.get('priority_tests', [])}\n"
                        f"- 可跳过: {strategy.get('skip_tests', [])}\n"
                        f"- Payload 建议: {json.dumps(strategy.get('payload_overrides', {}), ensure_ascii=False)}\n"
                        f"- 绕过技巧: {strategy.get('bypass_hints', [])}\n"
                        f"- 风险区域: {strategy.get('risk_areas', [])}\n"
                    )
                    logger.info("[loop] 加载历史知识: %s", strategy.get("reasoning", "")[:100])
            except Exception as e:
                logger.warning("[loop] 知识加载失败: %s", e)

        # 注入初始任务
        task_prompt = f"请对目标 {target} 进行全面的安全评估。"
        if initial_context:
            task_prompt += f"\n\n以下是已有的侦察结果：\n{initial_context}"
        if knowledge_context:
            task_prompt += knowledge_context
        task_prompt += "\n\n请开始自主执行安全测试。"

        self.session.append(role="user", content=task_prompt)

        logger.info("[loop] Agent 循环启动 — 目标: %s, 最大轮次: %d", target, self.config.max_turns)

        # ---- 主循环（对齐 pi 双层 while）----
        while not self._should_stop():
            # 外层：检查 follow-up 消息
            follow_ups = await self._drain_followups()
            for msg in follow_ups:
                self.session.append(role="user", content=msg)

            # 内层：tool call 循环
            has_more_tools = True
            while has_more_tools and not self._should_stop():
                # 1. 注入 steering 消息
                await self._inject_steering()

                # 2. 构建 LLM 上下文
                messages = await self._build_messages()

                # 3. 调用 LLM
                try:
                    response = await self._call_llm(messages)
                except Exception as e:
                    # 错误编码进 context（对齐 pi handleRunFailure）
                    error_msg = f"[系统提示] LLM 调用失败: {str(e)}。请分析原因并尝试其他方法，不要放弃任务。"
                    self.session.append(role="system", content=error_msg)
                    logger.error("[loop] LLM 调用失败: %s", e)
                    has_more_tools = False
                    continue

                # 4. 解析响应
                text, tool_calls = self._parse_response(response)

                # 5. 记录 assistant 响应
                if text:
                    self.session.append(role="assistant", content=text)
                    logger.info("[loop] Turn %d: %s", self._turn_count, text[:100])

                # 6. 检查是否完成
                if self._task_complete:
                    logger.info("[loop] 任务完成！")
                    break

                # 7. 执行工具调用
                if tool_calls:
                    await self._execute_tool_calls(tool_calls)
                else:
                    # 无工具调用，本轮结束
                    has_more_tools = False

                # 8. 自动完成检查
                if self._report_generated and not self._task_complete:
                    # 报告已生成，自动标记任务完成
                    self._task_complete = True
                    self.session.append(
                        role="system",
                        content="[系统提示] 报告已生成，任务完成。",
                    )
                    logger.info("[loop] 报告已生成，自动完成任务")
                elif len(self._tested_vuln_types) >= 3 and not self._task_complete:
                    # 测试了 3+ 种漏洞，注入报告指令
                    vuln_list = ", ".join(sorted(self._tested_vuln_types))
                    self.session.append(
                        role="system",
                        content=f"[系统提示] 你已测试 {len(self._tested_vuln_types)} 种漏洞类型: {vuln_list}。"
                                f"请立即调用 generate_report(target='{self._target}') 生成报告。"
                                f"不要再执行新的测试。",
                    )
                    logger.info("[loop] 已测试 %d 种漏洞类型，注入报告指令",
                                len(self._tested_vuln_types))

                self._turn_count += 1

            # 内层结束，检查是否需要继续
            if self._task_complete:
                break

        # ---- 循环结束 ----
        elapsed = time.time() - self._start_time
        self.session.force_flush()

        stats = {
            "turns": self._turn_count,
            "elapsed": round(elapsed, 1),
            "task_complete": self._task_complete,
            "aborted": self._abort,
            "session": self.session.summary(),
            "llm_stats": self.llm.stats.summary(),
            "knowledge_extracted": 0,
        }

        # 提取并存储知识（经验积累）
        if self.knowledge and self._tested_vuln_types:
            try:
                tool_results = self.session.get_tool_results()
                findings_data = self.session.get_entries_by_role("tool")
                findings_summary = [
                    {"tool": e.tool_name, "result": e.tool_result}
                    for e in findings_data if e.tool_result
                ]
                extracted = await self.knowledge.extract_from_scan(
                    self.llm, target, [], findings_summary, tool_results,
                )
                stats["knowledge_extracted"] = len(extracted)
                logger.info("[knowledge] 提取 %d 条经验", len(extracted))
            except Exception as e:
                logger.warning("[knowledge] 经验提取失败: %s", e)

        logger.info("[loop] Agent 循环结束 — %d 轮, %.1fs, 完成=%s",
                     self._turn_count, elapsed, self._task_complete)

        return stats

    def steer(self, message: str):
        """注入 steering 消息（用户实时指令）"""
        self._steering_queue.put_nowait(message)
        logger.info("[loop] Steering 注入: %s", message[:50])

    def follow_up(self, message: str):
        """注入 follow-up 消息（Agent 停止后继续）"""
        self._followup_queue.put_nowait(message)

    def abort(self):
        """中断 Agent"""
        self._abort = True
        logger.info("[loop] 收到中断信号")

    # ---- 内部方法 ----

    def _should_stop(self) -> bool:
        """检查终止条件（对齐 pi shouldStopAfterTurn）"""
        if self._abort:
            return True
        if self._task_complete:
            return True
        if self._turn_count >= self.config.max_turns:
            logger.warning("[loop] 达到最大轮次 %d", self.config.max_turns)
            return True
        if time.time() - self._start_time > self.config.max_time:
            logger.warning("[loop] 达到最大运行时间 %ds", self.config.max_time)
            return True
        return False

    async def _inject_steering(self):
        """注入 steering 消息到 session（对齐 pi steering 注入时机）"""
        while not self._steering_queue.empty():
            try:
                msg = self._steering_queue.get_nowait()
                self.session.append(
                    role="user",
                    content=f"[用户指令] {msg}",
                    metadata={"type": "steering"},
                )
            except asyncio.QueueEmpty:
                break

    async def _drain_followups(self) -> list[str]:
        """排空 follow-up 队列"""
        messages = []
        while not self._followup_queue.empty():
            try:
                messages.append(self._followup_queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        return messages

    async def _build_messages(self) -> list[dict[str, str]]:
        """构建 LLM 消息列表（含工具定义 + 上下文压缩 + 孤立消息清理）"""
        messages = self.session.build_context()

        # 上下文压缩检查
        if self.compressor and self.config.compaction_enabled:
            target = self.session.get_entries_by_role("system")
            target_name = target[0].metadata.get("target", "") if target else ""
            messages = await self.compressor.compact(messages, target=target_name)

        # 安全网：清理孤立的 tool 消息（防止 400 错误）
        messages = ContextCompressor._clean_orphaned_tools(messages)

        return messages

    async def _call_llm(self, messages: list[dict[str, str]]) -> str:
        """调用 LLM（带工具定义和 prompt cache）"""
        # 构建带工具定义的请求
        tool_schemas = self.tools.get_schemas_for_llm()

        # 添加内置 load_skill 工具
        tool_schemas.append({
            "type": "function",
            "function": {
                "name": "load_skill",
                "description": "加载安全测试知识库中的 skill。按需加载，省 token。获取针对性 payload、绕过技巧、检测方法。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "vuln_type": {
                            "type": "string",
                            "description": "漏洞类型，如 sqli, xss, ssrf, idor, graphql, jwt, ssti, nosqli, xxe, cors, csrf, upload, cmd_injection, race_condition, request_smuggling 等",
                        },
                    },
                    "required": ["vuln_type"],
                },
            },
        })

        # DeepSeek 兼容 OpenAI 格式
        response = await self.llm.chat_with_tools(
            messages=messages,
            tools=tool_schemas if tool_schemas else None,
        )

        return response

    def _parse_response(self, response: str) -> tuple[str, list[dict[str, Any]]]:
        """解析 LLM 响应，提取文本和工具调用

        DeepSeek 的 function calling 返回格式：
        {"role": "assistant", "content": "...", "tool_calls": [...]}
        """
        text = ""
        tool_calls = []

        try:
            # 尝试解析 JSON 响应
            data = json.loads(response) if response.strip().startswith("{") else {}
            text = data.get("content", response)
            tool_calls = data.get("tool_calls", [])
        except json.JSONDecodeError:
            text = response

        return text, tool_calls

    async def _execute_tool_calls(self, tool_calls: list[dict[str, Any]]):
        """执行工具调用（对齐 pi tool execution）"""
        # 转换为 (name, args) 列表
        calls = []
        for tc in tool_calls:
            func = tc.get("function", {})
            name = func.get("name", "")
            args_str = func.get("arguments", "{}")
            try:
                args = json.loads(args_str) if isinstance(args_str, str) else args_str
            except json.JSONDecodeError:
                args = {}
            if name:
                calls.append((name, args))

        if not calls:
            return

        # 分离内置工具和注册工具
        builtin_calls = []
        registry_calls = []
        skipped = []
        for name, args in calls:
            if name == "load_skill":
                builtin_calls.append((name, args))
            else:
                # 去重：相同工具 + 相同目标 URL 不重复调用
                dedup_key = f"{name}:{args.get('url', '')}{args.get('endpoint', '')}{args.get('base_url', '')}{args.get('host', '')}"
                if dedup_key in self._tested_pairs:
                    skipped.append(name)
                    continue
                self._tested_pairs.add(dedup_key)
                # 记录已测试的漏洞类型
                if name.startswith("test_"):
                    self._tested_vuln_types.add(name.replace("test_", ""))
                registry_calls.append((name, args))

        if skipped:
            logger.info("[loop] 跳过重复调用: %s", ", ".join(set(skipped)))

        # 执行内置工具（load_skill）
        for name, args in builtin_calls:
            vuln_type = args.get("vuln_type", "")
            skill_content = self.skill_loader.load_for_vuln_type(vuln_type)
            if not skill_content:
                skill_content = f"未找到 {vuln_type} 类型的 skill。可用类型: {', '.join(self.skill_loader.available_skills[:20])}"
            result = ToolResult(content=skill_content[:3000])
            self.session.append(
                role="tool", content=result.content,
                tool_name=name, tool_args=args,
                tool_result=result.to_dict(),
            )

        # 批量执行注册工具（根据 executionMode 自动决定并行/串行）
        results = await self.tools.execute_batch(registry_calls)
        calls = registry_calls  # 后续只处理注册工具的结果

        # 记录结果到 session
        for (name, args), result in zip(calls, results):
            self.session.append(
                role="tool",
                content=result.content,
                tool_name=name,
                tool_args=args,
                tool_result=result.to_dict(),
                is_error=result.is_error,
            )

            # 检查是否需要终止
            if result.terminate:
                self._task_complete = True
                break
            # 标记报告已生成
            if name == "generate_report" and not result.is_error:
                self._report_generated = True

        # 检查 complete_task 调用
        for name, _ in calls:
            if name == "complete_task":
                self._task_complete = True
                break

        # 卡住检测：连续调用相同分析工具 3 次，注入强制行动指令
        for name, _ in calls:
            self._recent_tools.append(name)
        self._recent_tools = self._recent_tools[-10:]  # 只保留最近 10 个

        analysis_tools = {"get_findings_summary", "analyze_findings"}
        recent_analysis = [t for t in self._recent_tools[-3:] if t in analysis_tools]
        if len(recent_analysis) >= 3:
            self.session.append(
                role="system",
                content="[系统提示] 你已连续 3 轮只做分析没有执行测试。"
                        "请立即调用 test_sqli、test_xss、test_idor、test_graphql 等扫描工具执行实际测试。"
                        "不要再调用 get_findings_summary 或 analyze_findings。",
            )
            self._recent_tools.clear()
            logger.warning("[loop] 检测到分析循环，注入强制行动指令")
