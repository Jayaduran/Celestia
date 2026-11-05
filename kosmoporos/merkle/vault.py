"""
Kosmoporos Cryptographic Merkle Vault.
Implements 125-log/block balanced binary Merkle trees for tamper-evident
digital evidence custody conforming to Section 65B Indian Evidence Act.
Accelerated via Kosmoporos C Core with seamless Python fallback.
"""

import hashlib
import ctypes
from typing import List, Dict, Any, Optional
from ..c_core.bindings import (
    is_c_core_available,
    _lib,
    _KosmoporosMerkleProof,
    c_sha256_hex,
)


class MerkleBlock:
    """A single Merkle Tree block holding up to block_size leaves."""

    def __init__(self, block_id: int, block_size: int = 125):
        self.block_id = block_id
        self.block_size = block_size
        self.leaf_hashes: List[str] = []
        self.root_hash: str = ""
        self.is_sealed: bool = False
        self._c_handle: Optional[ctypes.c_void_p] = None

        if is_c_core_available() and _lib:
            self._c_handle = _lib.kosmoporos_merkle_block_create(block_size, block_id)

    def __del__(self):
        if self._c_handle and _lib:
            try:
                _lib.kosmoporos_merkle_block_free(self._c_handle)
                self._c_handle = None
            except Exception:
                pass

    def append(self, raw_or_hash: str, is_hash: bool = False) -> bool:
        """Append leaf to block."""
        if self.is_sealed or len(self.leaf_hashes) >= self.block_size:
            return False

        if is_hash:
            h = raw_or_hash.lower()
        else:
            h = c_sha256_hex(raw_or_hash.encode("utf-8"))

        self.leaf_hashes.append(h)

        if self._c_handle and _lib:
            _lib.kosmoporos_merkle_block_append_hex(self._c_handle, h.encode("ascii"))
        return True

    def seal(self) -> str:
        """Compute the binary Merkle root hash for all leaves in this block."""
        if not self.leaf_hashes:
            self.root_hash = "0" * 64
            self.is_sealed = True
            return self.root_hash

        if self._c_handle and _lib:
            _lib.kosmoporos_merkle_block_seal(self._c_handle)
            buf = ctypes.create_string_buffer(65)
            _lib.kosmoporos_merkle_block_get_root_hex(self._c_handle, buf)
            self.root_hash = buf.value.decode("ascii")
            self.is_sealed = True
            return self.root_hash

        # Pure Python fallback
        current_level = [bytes.fromhex(h) for h in self.leaf_hashes]
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                combined = hashlib.sha256(left + right).digest()
                next_level.append(combined)
            current_level = next_level

        self.root_hash = current_level[0].hex()
        self.is_sealed = True
        return self.root_hash

    def verify_integrity(self) -> bool:
        """Check if any leaf hash or root has been tampered with."""
        if not self.is_sealed or not self.leaf_hashes:
            return True

        # Verify python leaf hashes match sealed root
        try:
            current_level = [bytes.fromhex(h) for h in self.leaf_hashes]
            while len(current_level) > 1:
                next_level = []
                for i in range(0, len(current_level), 2):
                    left = current_level[i]
                    right = current_level[i + 1] if i + 1 < len(current_level) else left
                    combined = hashlib.sha256(left + right).digest()
                    next_level.append(combined)
                current_level = next_level

            if current_level[0].hex() != self.root_hash:
                return False
        except Exception:
            return False

        if self._c_handle and _lib:
            return bool(_lib.kosmoporos_merkle_block_verify_integrity(self._c_handle))

        return True


class KosmoporosMerkleVault:
    """
    Continuous Merkle Tree Forest Vault.
    Maintains 125-log blocks, sealing each block automatically and forming
    an immutable cryptographic chain of custody.
    """

    def __init__(self, block_size: int = 125):
        self.block_size = block_size
        self.blocks: List[MerkleBlock] = []
        self.current_block: MerkleBlock = MerkleBlock(block_id=0, block_size=self.block_size)
        self.sealed_roots: List[str] = []
        self.total_leaves: int = 0
        self.total_tamper_detected: int = 0

    def append_event(self, raw_payload: str, event_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Append a raw log event to the active Merkle tree block.
        Automatically seals and starts a new block once capacity (125) is reached.
        """
        raw_hash = c_sha256_hex(raw_payload.encode("utf-8"))
        leaf_idx = len(self.current_block.leaf_hashes)

        self.current_block.append(raw_hash, is_hash=True)
        self.total_leaves += 1

        sealed_info = None
        if len(self.current_block.leaf_hashes) >= self.block_size:
            root = self.current_block.seal()
            self.sealed_roots.append(root)
            self.blocks.append(self.current_block)
            sealed_info = {
                "block_id": self.current_block.block_id,
                "root_hash": root,
                "leaf_count": len(self.current_block.leaf_hashes),
            }
            # Start next block
            self.current_block = MerkleBlock(block_id=len(self.blocks), block_size=self.block_size)

        return {
            "leaf_hash": raw_hash,
            "block_id": self.current_block.block_id if not sealed_info else sealed_info["block_id"],
            "leaf_index": leaf_idx,
            "sealed_block": sealed_info,
        }

    def seal_current_block(self) -> Optional[str]:
        """Force-seal the current open block (e.g. on shutdown or periodic checkpoint)."""
        if not self.current_block.leaf_hashes:
            return None
        root = self.current_block.seal()
        self.sealed_roots.append(root)
        self.blocks.append(self.current_block)
        self.current_block = MerkleBlock(block_id=len(self.blocks), block_size=self.block_size)
        return root

    def verify_block(self, block_id: int) -> bool:
        """Verify cryptographic integrity of any historical block."""
        if block_id < 0 or block_id >= len(self.blocks):
            if block_id == self.current_block.block_id:
                return self.current_block.verify_integrity()
            return False
        return self.blocks[block_id].verify_integrity()

    def get_latest_root(self) -> str:
        """Return the latest sealed Merkle Root hash, or active root."""
        if self.sealed_roots:
            return self.sealed_roots[-1]
        if self.current_block.leaf_hashes:
            current_level = [bytes.fromhex(h) for h in self.current_block.leaf_hashes]
            while len(current_level) > 1:
                next_level = []
                for i in range(0, len(current_level), 2):
                    left = current_level[i]
                    right = current_level[i + 1] if i + 1 < len(current_level) else left
                    combined = hashlib.sha256(left + right).digest()
                    next_level.append(combined)
                current_level = next_level
            return current_level[0].hex()
        return "0" * 64

    def get_metrics(self) -> Dict[str, Any]:
        return {
            "block_size": self.block_size,
            "total_leaves": self.total_leaves,
            "total_events": self.total_leaves,
            "sealed_blocks_count": len(self.blocks),
            "total_blocks": len(self.blocks),
            "latest_sealed_root": self.sealed_roots[-1] if self.sealed_roots else None,
            "current_block_id": self.current_block.block_id,
            "current_block_leaves": len(self.current_block.leaf_hashes),
            "backend": "C-Core (Hardware-Accelerated)" if is_c_core_available() else "Python-Fallback",
        }
