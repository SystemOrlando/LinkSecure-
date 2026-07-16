from __future__ import annotations

import argparse
import asyncio

from linksecure.core.analyzer import Analyzer


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="linksecure", description="Validacion de seguridad de enlaces"
    )
    parser.add_argument("url", help="URL a analizar")
    parser.add_argument("--json", action="store_true", help="Salida en formato JSON")
    args = parser.parse_args()

    result = asyncio.run(Analyzer().analyze(args.url))

    if args.json:
        print(result.model_dump_json(indent=2))
        return

    print(f"URL:       {result.url}")
    print(f"Veredicto: {result.verdict.value}")
    print(f"Riesgo:    {result.riskScore}/100")
    print("Metodos:")
    for m in result.methods:
        print(f"  [{m.status.value.upper():4}] {m.name}: {m.detail}")


if __name__ == "__main__":
    main()
