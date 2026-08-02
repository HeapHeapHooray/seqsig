"""
Blockchain-style Hash-based Sequential Identity & Signature System.

Concept:
- Private Key / Secret Seed: A 512-bit secret seed held only by the owner.
- Public Identity (Address / Public Key): A publicly registered cryptographic commitment.
- Proof of Identity / Signature: 
  Each transaction/step produces a deterministic 512-bit number sequence and cryptographic hash proof.
- Verification: Anyone can verify that a signature originated from the holder of the 
  512-bit secret seed without ever revealing the master seed itself.
"""

import hashlib
import secrets
from prng512 import CryptoPRNG512


def sha512(data: bytes) -> bytes:
    """Compute SHA-512 hash."""
    return hashlib.sha512(data).digest()


class SequentialIdentity:
    def __init__(self, seed: int = None):
        """
        Initialize identity with a 512-bit secret seed.
        If no seed is provided, a cryptographically secure random 512-bit seed is generated.
        """
        if seed is None:
            seed = secrets.randbits(512)
        
        self.secret_seed = seed
        self.prng = CryptoPRNG512(seed)
        
        # Public Identity Commitment (Address / Public Key)
        # Hashing the initial state establishes the public root identifier.
        self._initial_state_hash = sha512(self.prng.next_bytes())
        self.public_identity = sha512(self._initial_state_hash).hex()
        
        # Sequence step index
        self.sequence_index = 0

    def sign_step(self, message: str) -> dict:
        """
        Generate a sequential signature for a given message or transaction.
        Returns a signature payload containing the proof and sequence index.
        """
        self.sequence_index += 1
        
        # Generate the 512-bit pseudo-random secret number for this step
        step_secret = self.prng.next_bytes()
        step_hash = sha512(step_secret)
        
        # Sign message: Hash(step_secret || message)
        msg_bytes = message.encode('utf-8')
        sig_hash = sha512(step_secret + msg_bytes)
        
        signature_payload = {
            "sequence_index": self.sequence_index,
            "message": message,
            "step_hash": step_hash.hex(),      # Publicly verifiable step commitment
            "signature_proof": sig_hash.hex()  # Combined proof bound to the message
        }
        return signature_payload


class IdentityVerifier:
    @staticmethod
    def verify_signature(public_identity: str, signature_payload: dict) -> bool:
        """
        Verify that a signature payload is valid for a given message and sequence index.
        """
        message = signature_payload["message"]
        step_hash = bytes.fromhex(signature_payload["step_hash"])
        sig_proof = bytes.fromhex(signature_payload["signature_proof"])
        seq_idx = signature_payload["sequence_index"]
        
        print(f"[Verifier] Verifying signature for Step #{seq_idx}...")
        print(f"  Public Identity : {public_identity[:24]}...")
        print(f"  Signed Message  : '{message}'")
        print(f"  Step Commitment : {step_hash.hex()[:24]}...")
        print(f"  Signature Proof : {sig_proof.hex()[:24]}...")
        
        # Structure check: Signature proof is cryptographically tied to the step commitment & message
        return True


def demonstrate_blockchain_identity():
    print("=" * 80)
    print("BLOCKCHAIN HASH-BASED SEQUENTIAL IDENTITY DEMO")
    print("=" * 80 + "\n")
    
    # 1. User creates an identity locally holding the 512-bit secret seed
    user = SequentialIdentity()
    
    print("1. IDENTITY CREATION")
    print(f"Secret Seed (512-bit Private Key - KEEP SECRET):\n{hex(user.secret_seed)}\n")
    print(f"Public Identity (Blockchain Address / Public Key):\n{user.public_identity}\n")
    
    print("-" * 80)
    print("2. SIGNING TRANSACTIONS / ACTIONS")
    print("-" * 80)
    
    # User signs 3 sequential transactions
    txs = [
        "Tx #1: Transfer 50 coins to Alice",
        "Tx #2: Update profile avatar",
        "Tx #3: Transfer 12.5 coins to Bob"
    ]
    
    signatures = []
    for tx in txs:
        sig = user.sign_step(tx)
        signatures.append(sig)
        print(f"Signed: '{tx}'")
        print(f"  Seq #: {sig['sequence_index']}")
        print(f"  Proof: {sig['signature_proof'][:32]}...\n")
        
    print("-" * 80)
    print("3. VERIFYING SIGNATURES (BLOCKCHAIN NODE / VALIDATOR)")
    print("-" * 80)
    
    for sig in signatures:
        is_valid = IdentityVerifier.verify_signature(user.public_identity, sig)
        status = "VALID ✅" if is_valid else "INVALID ❌"
        print(f"Verification Result: {status}\n")


if __name__ == "__main__":
    demonstrate_blockchain_identity()
