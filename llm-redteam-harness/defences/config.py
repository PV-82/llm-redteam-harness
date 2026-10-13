from dataclasses import dataclass, fields

NAMES = ["input_filter", "hardened_prompt", "output_filter", "retrieval_allowlist", "tool_gate", "output_cap"]


@dataclass
class DefenceConfig:
    input_filter: bool = False        # regex deny-list + input length cap     (LLM01, LLM02, LLM07, LLM10)
    hardened_prompt: bool = False     # policy block appended to system prompt (LLM01, LLM02, LLM05, LLM06, LLM07)
    output_filter: bool = False       # redact secrets, escape HTML, strip ext. images (LLM02, LLM05, LLM07)
    retrieval_allowlist: bool = False # only trusted + public docs reach the model (LLM01 indirect, LLM08)
    tool_gate: bool = False           # least-privilege tool allow-list         (LLM06)
    output_cap: bool = False          # max output length                       (LLM10)

    @classmethod
    def none(cls):
        return cls()

    @classmethod
    def all(cls):
        return cls(**{n: True for n in NAMES})

    @classmethod
    def only(cls, name):
        return cls(**{name: True})

    def active(self):
        return [f.name for f in fields(self) if getattr(self, f.name)]
