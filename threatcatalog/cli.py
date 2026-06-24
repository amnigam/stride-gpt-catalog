"""
threatcatalog.cli
=================

Run a threat model from an intake JSON file, offline by default.

    python -m threatcatalog.cli intake.json --out report.md

Pass --llm to use a model-backed engine (requires ANTHROPIC_API_KEY and the
`anthropic` package). The deterministic engine needs neither.

Intake JSON shape:
{
  "profile": {"name": "...", "platforms": ["web","cloud"], "ai_capabilities": ["llm"],
              "data_classification": "Restricted", "handles_cardholder_data": false},
  "description": "free text ...",
  "declared": [{"control_id":"AI-PI-001","status":"not_present","provenance":"declared","confidence":"high"}],
  "observed_unmatched": [{"name":"PII tokenization","description":"masks on screen"}]
}
"""

from __future__ import annotations

import argparse
import json
import sys

from .models import AppProfile, LedgerEntry, ObservedControl
from .report import render_markdown


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Catalog-driven threat modeling")
    ap.add_argument("intake", help="path to intake JSON")
    ap.add_argument("--out", help="write Markdown report here (default: stdout)")
    ap.add_argument("--pdf", help="also write a PDF report to this path")
    ap.add_argument("--llm", action="store_true", help="use an LLM engine (needs API key)")
    ap.add_argument("--provider", choices=["anthropic", "openai"], default="anthropic",
                    help="which model provider to use with --llm")
    ap.add_argument("--model", default=None, help="model id (defaults per provider)")
    args = ap.parse_args(argv)

    data = json.loads(open(args.intake).read())
    profile = AppProfile.model_validate(data["profile"])
    declared = [LedgerEntry.model_validate(d) for d in data.get("declared", [])]
    observed = [ObservedControl.model_validate(o) for o in data.get("observed_unmatched", [])]

    from . import pipeline
    engine = None
    if args.llm:
        from .llm import AnthropicRawLLM, OpenAIRawLLM, LLMArtifactEngine
        if args.provider == "openai":
            raw = OpenAIRawLLM(model=args.model or "gpt-4o")
        else:
            raw = AnthropicRawLLM(model=args.model or "claude-sonnet-4-6")
        engine = LLMArtifactEngine(raw)

    report = pipeline.run(profile, description=data.get("description", ""),
                          declared=declared, observed_unmatched=observed, engine=engine)
    md = render_markdown(report)
    if args.pdf:
        from .pdf_export import render_pdf
        with open(args.pdf, "wb") as fh:
            fh.write(render_pdf(report))
        print(f"wrote {args.pdf}")
    if args.out:
        open(args.out, "w").write(md)
        print(f"wrote {args.out} ({len(report.threats)} threats, "
              f"{len(report.clarifications)} clarifications)")
    else:
        print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
