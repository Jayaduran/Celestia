import sys
from pathlib import Path

project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

from kosmoporos.engine import KosmoporosEngine

def verify_merkle():
    engine = KosmoporosEngine()
    print("="*50)
    print("MERKLE VAULT CRYPTOGRAPHIC INTEGRITY VERIFICATION")
    print("="*50)
    
    # Ingest mock logs to fill the vault
    print("Ingesting 300 mock logs to populate Merkle Vault blocks...")
    for i in range(300):
        engine.parse(f"Mock log entry number {i} for Merkle tree testing.")
        
    metrics = engine.merkle_vault.get_metrics()
    total_blocks = metrics.get('total_blocks', 0)
    total_events = metrics.get('total_events', 0)
    
    print(f"Total Logs Protected: {total_events}")
    print(f"Total Sealed Blocks (125 logs/block): {total_blocks}")
    
    if total_blocks == 0:
        print("\nNo sealed blocks to verify.")
        return
        
    print("\nVerifying SHA-256 Block Hashes...")
    passed = 0
    failed = 0
    
    for block_id in range(total_blocks):
        if engine.verify_merkle_block(block_id):
            passed += 1
        else:
            failed += 1
            print(f"[!] INTEGRITY VIOLATION DETECTED IN BLOCK {block_id}")
            
    print("-" * 50)
    print(f"Blocks Verified: {passed}/{total_blocks}")
    
    if failed == 0:
        print("[VERDICT: 100% PASSED] - Cryptographic chain of custody is mathematically intact.")
    else:
        print(f"[VERDICT: FAILED] - {failed} blocks failed cryptographic verification.")
    print("="*50)

if __name__ == '__main__':
    verify_merkle()
