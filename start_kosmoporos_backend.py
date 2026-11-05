import os
import sys
import time
from pathlib import Path

# Add project root and main to sys.path so kosmoporos module is discoverable
project_root = Path(__file__).resolve().parent.parent
main_dir = Path(__file__).resolve().parent
for p in [str(project_root), str(main_dir)]:
    if p not in sys.path:
        sys.path.insert(0, p)

from kosmoporos.spool_reader import SpoolReader


def main():
    spool_file = project_root / 'data' / 'spool' / 'ingest_stream.raw'
    
    # Ensure spool dir exists
    spool_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Ensure spool file exists before tailing
    if not spool_file.exists():
        spool_file.touch()

    reader = SpoolReader(spool_file=str(spool_file))
    
    try:
        reader.start()
        print("Kosmoporos Backend is running. Press Ctrl+C to stop.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping Kosmoporos Backend...")
        reader.stop()


if __name__ == '__main__':
    main()
