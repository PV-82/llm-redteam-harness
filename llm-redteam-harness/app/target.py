"""The deliberately vulnerable RAG chatbot. Each defence is a toggle in DefenceConfig."""
import re
from dataclasses import dataclass, field

from defences import filters
from defences.config import DefenceConfig

from .config import BASE_SYSTEM, HARDENED_POLICY
from .knowledge import retrieve
from .tools import REGISTRY


@dataclass
class ToolCall:
    name: str
    args: str
    executed: bool
    note: str = ""


@dataclass
class Response:
    text: str
    tool_calls: list = field(default_factory=list)
    blocked_by: str = None
    retrieved: list = field(default_factory=list)


class TargetApp:
    def __init__(self, backend, defences=None):
        self.backend = backend
        self.d = defences or DefenceConfig.none()

    def respond(self, user):
        if self.d.input_filter:
            reason = filters.input_check(user)
            if reason:
                return Response("Request blocked by input filter.", blocked_by=f"input_filter: {reason}")

        docs = retrieve(user)
        if self.d.retrieval_allowlist:
            docs = [x for x in docs if filters.doc_allowed(x)]
        system = BASE_SYSTEM + ("\n" + HARDENED_POLICY if self.d.hardened_prompt else "")
        text = self.backend.complete(system, [x.text for x in docs], user)

        calls = []
        for name, args in re.findall(r"TOOL_CALL:\s*(\w+)\((.*?)\)", text):
            if name not in REGISTRY:
                calls.append(ToolCall(name, args, False, "unknown tool"))
            elif self.d.tool_gate and not filters.tool_allowed(name):
                calls.append(ToolCall(name, args, False, "blocked by tool gate (needs human approval)"))
            else:
                REGISTRY[name](args)
                calls.append(ToolCall(name, args, True))

        if self.d.output_filter:
            text = filters.output_sanitise(text)
        if self.d.output_cap:
            text = filters.output_cap(text)
        return Response(text, calls, None, [x.id for x in docs])
