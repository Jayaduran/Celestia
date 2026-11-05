import sys
from pathlib import Path

# Add project root and main to sys.path so kosmoporos module is discoverable
project_root = Path(__file__).resolve().parent.parent
main_dir = Path(__file__).resolve().parent
for p in [str(project_root), str(main_dir)]:
    if p not in sys.path:
        sys.path.insert(0, p)

from kosmoporos.ai_sidecar import AiSidecar


def main():
    sidecar = AiSidecar()
    try:
        sidecar.start()
    except KeyboardInterrupt:
        sidecar.stop()


if __name__ == '__main__':
    main()
