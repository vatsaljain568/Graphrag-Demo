# Jenkins Plugin Knowledge Graph

This project builds a directed knowledge graph of Jenkins plugins using **NetworkX**, enabling:
- Multi-hop dependency and conflict traversal
- CVE-to-plugin relationship tracking
- Confidence-based query routing (Graph vs. Vector path)
- Visual graph rendering

It serves as the **graph intelligence layer** for an AI-powered Jenkins assistant — routing relational queries to structured graph traversal while delegating semantic/general queries to a FAISS vector store.

---


## Graph Schema

### Node Types

| Type | Description | Example |
|---|---|---|
| `Plugin` | A Jenkins plugin | `blueocean-plugin` |
| `CVE` | A known vulnerability | `CVE-2024-1234` |
| `Version` | A plugin version | `v4.1` |

### Edge Types (Relations)

| Relation | Meaning |
|---|---|
| `DEPENDS_ON` | Plugin A requires Plugin B |
| `CONFLICTS_WITH` | Plugin A is incompatible with Plugin B |
| `HAS_CVE` | Plugin is affected by a CVE |
| `FIXED_IN` | CVE is resolved in a specific version |

---

### Prerequisites

```bash
pip install -r requirements.txt
```

### Run

```bash
python test.py
```
