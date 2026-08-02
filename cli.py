#!/usr/bin/env python3
"""
CLI Tool for Ledgerless 512-Bit Secret Seed Block Minting & Nonce Verification.
"""

import argparse
import hashlib
import json
import os
import secrets
import sys
import time

from prng512 import CryptoPRNG512
from blockchain_seed_nonce import (
    save_block_to_txt,
    parse_block_txt,
    sha512_int,
    sha512_bytes
)


def cmd_gen_seed(args):
    """Generate a new 512-bit master secret seed and print public address."""
    seed = secrets.randbits(512)
    hex_seed = hex(seed)
    
    # Calculate Public Identity Commitment
    prng = CryptoPRNG512(seed)
    initial_state_hash = hashlib.sha512(prng.next_bytes()).digest()
    public_identity = hashlib.sha512(initial_state_hash).hexdigest()
    
    if args.json:
        out_dict = {
            "secret_seed": hex_seed,
            "public_identity": public_identity
        }
        json_str = json.dumps(out_dict, indent=2)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(json_str + "\n")
            print(f"Saved identity JSON to: {args.out}")
        else:
            print(json_str)
    else:
        print("=" * 80)
        print("512-BIT SECRET SEED & PUBLIC IDENTITY GENERATOR")
        print("=" * 80)
        print(f"\nMaster Secret Seed (512-bit Private Key - KEEP SECRET):\n{hex_seed}\n")
        print(f"Public Identity (Blockchain Address / Public Key):\n{public_identity}\n")
        
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(hex_seed + "\n")
            print(f"Saved secret seed to file: {args.out}")


def load_seed_from_arg_or_file(seed_input: str) -> int:
    """Load 512-bit integer seed from hex string or file path."""
    if os.path.exists(seed_input):
        with open(seed_input, "r", encoding="utf-8") as f:
            content = f.read().strip()
            # If secret seed was saved inside JSON format
            if content.startswith("{"):
                try:
                    data = json.loads(content)
                    seed_input = data.get("secret_seed") or data.get("seed", content)
                except Exception:
                    pass
            else:
                seed_input = content
    
    try:
        if seed_input.startswith("0x") or seed_input.startswith("0X"):
            val = int(seed_input, 16)
        else:
            val = int(seed_input, 16 if all(c in "0123456789abcdefABCDEF" for c in seed_input) else 10)
        return val
    except ValueError:
        print(f"Error: Invalid seed format '{seed_input}'. Expected 512-bit hex string or seed file.")
        sys.exit(1)


def load_json_input(input_arg: str = None) -> dict:
    """Load JSON payload from file path or stdin."""
    json_raw = None
    if input_arg and input_arg != "-":
        if os.path.exists(input_arg):
            with open(input_arg, "r", encoding="utf-8") as f:
                json_raw = f.read()
        else:
            json_raw = input_arg
    else:
        # Read from stdin if piped or input_arg is '-'
        if not sys.stdin.isatty() or input_arg == "-":
            json_raw = sys.stdin.read()

    if json_raw:
        try:
            return json.loads(json_raw)
        except Exception as e:
            print(f"Error parsing JSON input: {e}")
            sys.exit(1)
    return None


def cmd_mint_block(args):
    """
    Mint a standalone block based strictly on provided block.json input from file or stdin.
    No ledger database or ledger state required!
    """
    block_json_data = load_json_input(args.json_file)
    
    seed_arg = None
    data_arg = None
    block_index = 0
    prev_hash = "0" * 128
    
    if block_json_data:
        seed_arg = block_json_data.get("seed") or block_json_data.get("secret_seed")
        data_arg = block_json_data.get("data")
        block_index = block_json_data.get("index", block_json_data.get("block_index", 0))
        prev_hash = block_json_data.get("prev_hash", "0" * 128)
        
    if not seed_arg and getattr(args, "seed", None):
        seed_arg = args.seed
    if not data_arg and getattr(args, "data", None):
        data_arg = args.data

    if not seed_arg or not data_arg:
        print("Error: Missing required 'seed' or 'data' in block JSON or arguments.")
        print("Expected block.json format: {\"seed\": \"<seed_or_key_file>\", \"data\": \"<transaction_data>\", \"index\": 0}")
        sys.exit(1)

    seed_val = load_seed_from_arg_or_file(seed_arg)
    
    # Initialize PRNG engine and advance to step index
    prng = CryptoPRNG512(seed_val)
    for _ in range(block_index):
        prng.next_bytes()
        
    start_time = time.perf_counter()
    nonce_curr = prng.next_int()
    h_curr = sha512_int(nonce_curr)
    
    block_content = (prev_hash + data_arg + h_curr.hex()).encode('utf-8')
    block_hash = sha512_bytes(block_content).hex()
    elapsed_us = (time.perf_counter() - start_time) * 1_000_000
    
    minted_block = {
        "index": block_index,
        "data": data_arg,
        "prev_hash": prev_hash,
        "nonce_N_i": hex(nonce_curr),
        "nonce_hash_H_Ni": h_curr.hex(),
        "block_hash": block_hash,
        "time_to_know_nonce": f"{elapsed_us:.2f} µs (INSTANT)"
    }
    
    # Handle output destination
    if args.txt_out:
        save_block_to_txt(minted_block, args.txt_out)
        print(f"Saved text block to: {args.txt_out}")
        
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(minted_block, f, indent=2)
            f.write("\n")
        print(f"Saved minted block JSON to: {args.out}")
    elif not args.txt_out:
        # Default: Print JSON to stdout
        print(json.dumps(minted_block, indent=2))


def cmd_verify_block(args):
    """Verify integrity of a standalone block JSON or .txt file."""
    filepath = args.file
    if not os.path.exists(filepath):
        print(f"Error: File '{filepath}' not found.")
        sys.exit(1)
        
    block = None
    if filepath.endswith(".json"):
        with open(filepath, "r", encoding="utf-8") as f:
            block = json.load(f)
    else:
        block = parse_block_txt(filepath)
        if not block:
            # Try parsing as JSON if filename doesn't end with .json
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    block = json.load(f)
            except Exception:
                pass

    if not block:
        print(f"Error: Could not parse block from '{filepath}'.")
        sys.exit(1)
        
    print("=" * 80)
    print(f"VERIFYING STANDALONE BLOCK #{block.get('index', 0)}")
    print("=" * 80)
    print(f"  Data               : '{block.get('data')}'")
    print(f"  Prev Hash          : {block.get('prev_hash')[:32]}...")
    print(f"  Nonce N_i          : {block.get('nonce_N_i')[:32]}...")
    print(f"  Nonce Commitment   : {block.get('nonce_hash_H_Ni')[:32]}...")
    print(f"  Block Hash         : {block.get('block_hash')[:32]}...")
    
    # 1. Verify nonce commitment H(N_i)
    nonce_int = int(block["nonce_N_i"], 16)
    calc_h_curr = sha512_int(nonce_int).hex()
    if calc_h_curr != block["nonce_hash_H_Ni"]:
        print("\n❌ RESULT: INVALID NONCE COMMITMENT! H(N_i) does not match N_i!")
        sys.exit(1)
        
    # 2. Verify block hash calculation
    block_content = (block["prev_hash"] + block["data"] + calc_h_curr).encode('utf-8')
    calc_block_hash = sha512_bytes(block_content).hex()
    if calc_block_hash != block["block_hash"]:
        print("\n❌ RESULT: INVALID BLOCK HASH! Content or hash was tampered with!")
        sys.exit(1)
        
    print("\n✅ RESULT: BLOCK IS CRYPTOGRAPHICALLY VALID!")


def cmd_parse_block(args):
    """Parse a block .txt or .json file and output JSON to file or stdout."""
    filepath = args.file
    if not os.path.exists(filepath):
        print(f"Error: File '{filepath}' not found.")
        sys.exit(1)
        
    if filepath.endswith(".json"):
        with open(filepath, "r", encoding="utf-8") as f:
            block = json.load(f)
    else:
        block = parse_block_txt(filepath)
        
    if not block:
        print(f"Error: Could not parse block data from '{filepath}'.")
        sys.exit(1)

    json_str = json.dumps(block, indent=2)
    
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(json_str + "\n")
        print(f"Successfully parsed '{filepath}' and saved JSON to '{args.out}'")
    else:
        print(json_str)


def cmd_attack_sim(args):
    """Simulate an attacker attempting to brute-force a block nonce without the seed."""
    filepath = args.file
    if not os.path.exists(filepath):
        print(f"Error: File '{filepath}' not found.")
        sys.exit(1)
        
    block = None
    if filepath.endswith(".json"):
        with open(filepath, "r", encoding="utf-8") as f:
            block = json.load(f)
    else:
        block = parse_block_txt(filepath)
        
    if not block:
        print(f"Error: Could not parse block from '{filepath}'.")
        sys.exit(1)
        
    target_hash_hex = block["nonce_hash_H_Ni"]
    
    print("=" * 80)
    print(f"OUTSIDER ATTACK SIMULATION (Targeting Block #{block.get('index', 0)})")
    print("=" * 80)
    print(f"Target Nonce Commitment H(N_i): {target_hash_hex}")
    print(f"Searching 512-bit nonce space without the secret seed...\n")
    
    start_time = time.perf_counter()
    attempts = 0
    max_attempts = args.attempts
    target_bytes = bytes.fromhex(target_hash_hex)
    
    for _ in range(max_attempts):
        attempts += 1
        guess = secrets.randbits(512)
        if sha512_int(guess) == target_bytes:
            print(f"SUCCESS after {attempts} attempts!")
            return
            
    elapsed = time.perf_counter() - start_time
    print(f"FAILED after {attempts:,} attempts ({elapsed:.3f}s).")
    print(f"Estimated time to guess 2^512 nonces: ~10^138 universe lifetimes!")
    print("The seed holder knows this nonce instantly in ~5 microseconds!\n")


def main():
    parser = argparse.ArgumentParser(
        description="Ledgerless 512-Bit Secret Seed Block Minting & Nonce Verification CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Command: gen-seed
    p_gen = subparsers.add_parser("gen-seed", help="Generate a 512-bit secret seed and public address")
    p_gen.add_argument("-o", "--out", help="File path to save secret seed or identity JSON")
    p_gen.add_argument("-j", "--json", action="store_true", help="Output identity as JSON")
    p_gen.set_defaults(func=cmd_gen_seed)
    
    # Command: mint
    p_mint = subparsers.add_parser("mint", help="Mint a block from block.json input (file or stdin)")
    p_mint.add_argument("json_file", nargs="?", default=None, help="Path to block.json file or '-' for stdin")
    p_mint.add_argument("-s", "--seed", help="512-bit secret seed (hex string or file path)")
    p_mint.add_argument("-d", "--data", help="Data / Transaction message for the block")
    p_mint.add_argument("-o", "--out", help="Output JSON file path for minted block")
    p_mint.add_argument("-t", "--txt-out", help="Output .txt file path for minted block")
    p_mint.set_defaults(func=cmd_mint_block)
    
    # Command: verify
    p_verify = subparsers.add_parser("verify", help="Verify the integrity of a block file (.json or .txt)")
    p_verify.add_argument("file", help="Path to block file (.json or .txt)")
    p_verify.set_defaults(func=cmd_verify_block)
    
    # Command: parse_block & parse-block
    for name in ["parse_block", "parse-block"]:
        p_parse = subparsers.add_parser(name, help="Parse a block file into JSON format")
        p_parse.add_argument("file", help="Input .txt or .json block file path")
        p_parse.add_argument("-o", "--out", help="Output JSON file path")
        p_parse.set_defaults(func=cmd_parse_block)
    
    # Command: attack
    p_attack = subparsers.add_parser("attack", help="Simulate brute-force attack on a block nonce without seed")
    p_attack.add_argument("file", help="Path to target block file (.json or .txt)")
    p_attack.add_argument("-a", "--attempts", type=int, default=100000, help="Number of brute-force attempts")
    p_attack.set_defaults(func=cmd_attack_sim)
    
    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        sys.exit(1)
        
    args.func(args)


if __name__ == "__main__":
    main()
