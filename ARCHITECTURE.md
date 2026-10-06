# Architecture

```mermaid
flowchart LR
  subgraph Sources[Data sources - connectors.py]
    S1[Instagram / X / Facebook / LinkedIn]
    S2[TikTok - may be unavailable]
    S3[Google Play / App Store]
  end
  BP[(Brand profile<br/>names, aliases, domains,<br/>official handles + app ids,<br/>publishers, logo fingerprint,<br/>allow-list)]
  S1 & S2 & S3 -->|normalized candidates<br/>failures reported, never fatal| EX
  BP --> EX{Official asset?<br/>platform+handle / app id / publisher}
  EX -- yes --> SKIP[Skipped, counted only]
  EX -- no --> DET
  subgraph DET[Detection - detection.py]
    N[Look-alike names: spacing, character swaps,<br/>homoglyphs, typos, bait words]
    L[Logo fingerprint distance]
    C[Scam wording, off-brand links,<br/>description overlap]
    P[Publisher mismatch / imitation,<br/>account age, unverified]
  end
  DET --> SC[Score 0-100 + reasons<br/>gate: weak signals alone never flag]
  SC -->|>=25 low, >=45 medium, >=70 high| DB[(SQLite: detections,<br/>analyst status, scans)]
  DB --> UI[Web UI: profile, findings, quick check]
```

**How official assets are excluded:** the profile is checked before scoring. A candidate is dropped when its
platform+handle matches an official account, its app id matches an official app, or its publisher is an official
publisher. A name allow-list (e.g. "Acme Bakery") suppresses known harmless look-alikes. Analyst "dismissed" decisions persist across scans.

**Avoiding over-flagging:** name similarity is the primary signal. Contextual signals (publisher, account age, links, wording)
only add points when there is already name or logo evidence, and a harmless added word ("Acme Bank Fans") scores below the threshold.
