# LLM-SEC

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

> **Most security tools use AI to find bugs in your app. LLM-SEC finds the bugs in your AI.**

---

## The Gap No One Is Filling

The security industry is racing to build **AI-powered pentesters** — agents that scan APIs, chain exploits, and optimize for pass rates on known benchmarks. That's valuable work. It's also not what LLM-SEC does.

LLM-SEC is for the team shipping an LLM application — a RAG pipeline, an agent with tool access, a customer-facing chatbot with memory — and asking a harder question:

> *"Where does my AI system fail when an attacker thinks in chains, not in single prompts?"*

The vulnerabilities that matter in production aren't prompt injections that get caught by a safety classifier. They're:

- **Cross-component chains**: A poisoned embedding → retrieved as trusted context → triggers an unauthorized API call.
- **Stateful escalation**: An indirect injection that survives across conversation turns, gradually expanding what the model believes it can do.
- **Reconstructed leakage**: PII that evades regex because the LLM assembles it from benign fragments across multiple retrieved documents.
- **Agency bypass**: A model that executes critical actions without human confirmation because the guardrail only checked the output, not the decision path.

These failures don't show up on traditional pentest reports. They don't fit neatly into OWASP categories in isolation. They emerge from the interaction of components that were secure individually.

## What LLM-SEC Does Differently

### 1. Full-Stack Attack Chains
We don't test prompts. We test **systems**.

Our LangGraph-based engine models attacks as state machines: reconnaissance → injection → retrieval manipulation → generation exploitation → unauthorized action. Each step feeds into the next. If the chain breaks, you know exactly where your defense held — and where it didn't.

### 2. Tri-Stage PII Detection
Regex catches obvious leaks. NER catches named entities. Neither catches what happens when an LLM *reconstructs* sensitive information from fragments.

- **Stage 1**: Deterministic regex for high-confidence patterns
- **Stage 2**: spaCy NER for entity recognition in unstructured output
- **Stage 3**: Semantic LLM-as-a-Judge reasoning to flag *inferred* or *reconstructed* sensitive data

### 3. Vector Guard
Most RAG security stops at the prompt layer. LLM-SEC inspects the vector space:
- Adversarial signature detection in embeddings
- Steganographic payload identification in retrieved chunks
- Low-entropy DoS risks (poisoned queries triggering unbounded retrieval)

### 4. Excessive Agency Auditor
When LLMs have tool access, the vulnerability isn't what they *say* — it's what they *do*.

We audit the full decision path: map critical actions, validate human-in-the-loop checkpoints, and report bypass paths where low-privilege actions chain into high-privilege outcomes.

### 5. Validation-First Reporting
Every finding ships with:
- Full reproduction steps
- Exact attack chain (state transitions, retrieved context, generated output)
- Confidence score, not binary pass/fail
- OWASP LLM Top 10 mapping for compliance context

We optimize for **depth and reproducibility**, not zero-noise dashboards.

---

## Architecture

| Component | Purpose |
|---|---|
| **LangGraph Attack Engine** | Multi-step, stateful adversarial campaign orchestration |
| **Tri-Stage PII Auditor** | Regex → NER → Semantic reasoning for contextual data leakage |
| **Vector Guard** | Embedding-space adversarial inspection (Weaviate / Pinecone) |
| **Agency Auditor** | Critical action path analysis with HITL validation |
| **Eval Framework** | DeepEval / Giskard integrations for measurable, comparable results |

---

## Installation

```bash
git clone https://github.com/lucasmulato/llm-sec.git
cd llm-sec
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

## Quick Start

```bash
# Run a full-stack adversarial campaign against a RAG application
python -m llmsec campaign --target http://localhost:8000 --config configs/rag_fullstack.yml

# Inspect vector DB for adversarial embeddings
python -m llmsec vector-guard --db weaviate --collection documents

# Audit excessive agency in an agentic workflow
python -m llmsec agency-audit --spec agent_config.json
```

---

## Roadmap

- [x] Core CLI and Tri-Stage PII Scanner
- [x] LangGraph-based Adaptive Attack Engine
- [ ] RAG Poisoning & Vector DB Stress Testing (in progress)
- [ ] Automated cross-component exploit chaining (retrieval → generation → action)
- [ ] Full MCP Server integration for agentic environment testing

---

## Philosophy

> "Low false positives are nice. Finding the vulnerability that burns your production RAG pipeline is better. Validation is always required — human or AI — so we optimize for depth, not silence."

LLM-SEC is not a benchmark-optimization tool. It is a **production adversarial reasoning engine** for teams who need to understand how their LLM applications fail under realistic, multi-step attacks.

## License

MIT
