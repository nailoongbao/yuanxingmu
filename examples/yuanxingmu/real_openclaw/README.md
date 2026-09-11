# Real-model OpenClaw recording

The [public video](https://yh-l20.github.io/agent-defense-check/real-demo.html) shows genuine local Qwen3-4B inference in the native OpenClaw UI, with synthetic documents and independent test receivers.

Start with the [plain Chinese explanation](../../../docs/real-openclaw-demo.zh-CN.md) or the [detailed audit](evidence/REPORT.zh-CN.md). The wrong-file selection, wrong answer and subsequent user correction are retained. These records establish outcomes in one configured run, not a general attack protection rate.

`evidence/` is a frozen export of that run. Its manifest lists file sizes and SHA256 values; Git preserves the original bytes. `runtime-source/` preserves the code actually used for the recording and must not be substituted for the current package. One runtime module differs from released source, as documented in the audit.

`verify_session.py` extracts and correlates the original profile's native SQLite messages, broker and receiver records, model process identity and lifecycle observations. It needs the original local profile, which is deliberately not published because it includes configuration, credentials and state. The public export contains selected synthetic messages and sanitized records, not those databases.

The complete raw video, narrated edit, subtitles and exact cut metadata are included with [v0.3.0a1](https://github.com/yh-l20/agent-defense-check/releases/tag/v0.3.0a1). The older scripted-model recording and v0.2 release remain separate.
