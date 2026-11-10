#!/usr/bin/env python3
"""Validate the production continuity roadmap against Draft 2020-12."""
import json
from pathlib import Path
from jsonschema import Draft202012Validator,FormatChecker
ROOT=Path(__file__).resolve().parents[1]
def main():
 schema=json.loads((ROOT/"schemas/sovereignty-production-continuity.schema.json").read_text())
 roadmap=json.loads((ROOT/"roadmap/sovereignty-production-roadmap.json").read_text())
 Draft202012Validator.check_schema(schema)
 errors=sorted(Draft202012Validator(schema,format_checker=FormatChecker()).iter_errors(roadmap),key=lambda e:list(map(str,e.absolute_path)))
 if errors:
  for e in errors: print(f"FAIL {'.'.join(map(str,e.absolute_path)) or '$'}: {e.message}")
  return 1
 print("PASS: production continuity schema and roadmap validate");return 0
if __name__=="__main__": raise SystemExit(main())
