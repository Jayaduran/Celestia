import argparse
import sys
from pathlib import Path
from app.pipeline import UlpfPipeline
from app.detector.format_detector import FormatDetector


def run_cli():
    parser = argparse.ArgumentParser(
        description="ULPF (Universal Log Pre-processing Framework) Phase 1 CLI Tool"
    )
    parser.add_argument(
        "--file", "-f", type=str, help="Path to a sample log file to process"
    )
    parser.add_argument(
        "--log", "-l", type=str, help="Raw log message string to process directly"
    )

    args = parser.parse_args()

    if not args.file and not args.log:
        parser.print_help()
        sys.exit(1)

    log_messages = []
    if args.log:
        log_messages.append(args.log)
    elif args.file:
        filepath = Path(args.file)
        if not filepath.exists():
            print(f"Error: File not found at '{args.file}'", file=sys.stderr)
            sys.exit(1)
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line_str = line.strip()
                if line_str and not line_str.startswith("#"):
                    log_messages.append(line_str)

    pipeline = UlpfPipeline()
    detector = FormatDetector()

    for idx, raw_log in enumerate(log_messages, start=1):
        detection = detector.detect(raw_log)
        ir = pipeline.process(raw_log)

        print("\n" + "=" * 50)
        print(f"ULPF Processing Result [Log #{idx}]")
        print("=" * 50)
        print(f"Format:      {detection.format}")
        print(f"Confidence:  {detection.confidence:.2f}")
        print(f"Reason:      {detection.reason}")
        print(f"Status:      {ir.status.upper()}")
        if ir.reason:
            print(f"Parse Note:  {ir.reason}")

        print("\nNormalized Event")
        print("-" * 30)
        if ir.source.ip:
            print(f"source.ip:          {ir.source.ip}")
        if ir.source.port is not None:
            print(f"source.port:        {ir.source.port}")
        if ir.destination.ip:
            print(f"destination.ip:     {ir.destination.ip}")
        if ir.destination.port is not None:
            print(f"destination.port:   {ir.destination.port}")
        if ir.event.action:
            print(f"event.action:       {ir.event.action}")
        if ir.event.type:
            print(f"event.type:         {ir.event.type}")
        if ir.event.category:
            print(f"event.category:     {ir.event.category}")
        if ir.network.transport:
            print(f"network.transport:  {ir.network.transport}")
        if ir.network.protocol:
            print(f"network.protocol:   {ir.network.protocol}")
        if ir.device.vendor:
            print(f"device.vendor:      {ir.device.vendor}")
        if ir.device.product:
            print(f"device.product:     {ir.device.product}")
        if ir.device.hostname:
            print(f"device.hostname:    {ir.device.hostname}")
        if ir.rule.name:
            print(f"rule.name:          {ir.rule.name}")
        if ir.user.name:
            print(f"user.name:          {ir.user.name}")
        if ir.severity:
            print(f"severity:           {ir.severity}")

        print("\nOriginal SHA256:")
        print(ir.original.sha256)

        print("\nProvenance:")
        if ir.provenance:
            for canon_field, prov in ir.provenance.items():
                print(f"  {canon_field:<18} <- {prov.original_field} (val: {prov.original_value}) [{prov.parser}]")
        else:
            print("  (No fields mapped)")
        print()


if __name__ == "__main__":
    run_cli()
