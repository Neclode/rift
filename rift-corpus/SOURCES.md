# Sources

Every attack-path record in this corpus is a **generalization of a publicly documented technique** — a real, disclosed case abstracted into a reusable, in-scope pattern (not a verbatim copy). Each record's `source` / `source_id` / `raw_ref` fields point to the public original listed below, so any claim can be checked at the source.

## MITRE ATLAS case studies

Source: <https://atlas.mitre.org> — each ID below links to the public case study.

| Record | ATLAS ID | Case study |
|--------|----------|------------|
| ap-0024 | [AML.CS0016](https://atlas.mitre.org/studies/AML.CS0016) | Achieving Code Execution in MathGPT via Prompt Injection |
| ap-0025 | [AML.CS0020](https://atlas.mitre.org/studies/AML.CS0020) | Indirect Prompt Injection Threats: Bing Chat Data Pirate |
| ap-0026 | [AML.CS0024](https://atlas.mitre.org/studies/AML.CS0024) | Morris II Worm: RAG-Based Attack |
| ap-0027 | [AML.CS0026](https://atlas.mitre.org/studies/AML.CS0026) | Financial Transaction Hijacking with M365 Copilot as an Insider |
| ap-0028 | [AML.CS0035](https://atlas.mitre.org/studies/AML.CS0035) | Data Exfiltration from Slack AI via Indirect Prompt Injection |
| ap-0029 | [AML.CS0040](https://atlas.mitre.org/studies/AML.CS0040) | Hacking an AI Assistant's Memories with Prompt Injection |
| ap-0030 | [AML.CS0041](https://atlas.mitre.org/studies/AML.CS0041) | Rules File Backdoor: Supply Chain Attack on AI Coding Assistants |
| ap-0031 | [AML.CS0046](https://atlas.mitre.org/studies/AML.CS0046) | Data Destruction via Indirect Prompt Injection (computer-use agent) |
| ap-0032 | [AML.CS0029](https://atlas.mitre.org/studies/AML.CS0029) | Google Bard Conversation Exfiltration |
| ap-0033 | [AML.CS0039](https://atlas.mitre.org/studies/AML.CS0039) | Living Off AI: Prompt Injection via Jira Service Management |
| ap-0034 | [AML.CS0054](https://atlas.mitre.org/studies/AML.CS0054) | Data Exfiltration via Remote Poisoned MCP Tool |
| ap-0035 | [AML.CS0055](https://atlas.mitre.org/studies/AML.CS0055) | AI ClickFix: Hijacking Computer-Use Agents Using ClickFix |

## InjecAgent

Source: <https://github.com/uiuc-kang-lab/InjecAgent> — a benchmark for indirect prompt injection against tool-integrated LLM agents. These records adapt its attack **categories**, not individually-numbered cases.

| Record | Category |
|--------|----------|
| ap-0036 | direct-harm (attacker-named harmful tool call) |
| ap-0037 | data-stealing (read private data → send to attacker sink) |

## AgentDojo

Source: <https://github.com/ethz-spylab/agentdojo> — a dynamic benchmark of prompt-injection attacks and defenses across LLM-agent task suites. These records adapt its task-suite attack **patterns**.

| Record | Pattern |
|--------|---------|
| ap-0040 | workspace-exfil (injected document re-tasks a workspace agent to forward private data) |
| ap-0041 | banking-transfer-hijack (injected note redirects an agent-issued transfer) |

---

**On precision:** ATLAS records cite a specific, clickable case study. InjecAgent and AgentDojo define attack *classes* and programmatic task suites rather than individually-numbered public cases, so those records cite the benchmark and the category they generalize.
