#!/usr/bin/env python3
"""
CLI Tool for 512-Bit Secret Seed Sequential Blockchain Identity.

Model:
- Single Hash: nonce_hash = SHA-512(N_k)
- block_hash = SHA-512(current_data + nonce_hash)
- `nonce_hash` is NOT written in Block k! It only appears in Block k+1 as `previous_nonce`.
- Block k contains only: index, data, previous_nonce, block_hash.
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
    format_block_txt_str,
    sha512_int,
    sha512_bytes,
    compute_nonce_hash,
    compute_block_hash
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
    """Load JSON or TXT payload from file path or stdin."""
    raw_content = None
    if input_arg and input_arg != "-":
        if os.path.exists(input_arg):
            if input_arg.endswith(".txt"):
                return parse_block_txt(input_arg)
            with open(input_arg, "r", encoding="utf-8") as f:
                raw_content = f.read().strip()
        else:
            raw_content = input_arg
    else:
        # Read from stdin if piped or input_arg is '-'
        if not sys.stdin.isatty() or input_arg == "-":
            raw_content = sys.stdin.read().strip()

    if raw_content:
        if raw_content.startswith("="):
            # Parse text format from stdin
            lines = raw_content.splitlines()
            block = {}
            for line in lines:
                line = line.strip()
                if ":" in line:
                    key, val = line.split(":", 1)
                    key = key.strip().lower()
                    val = val.strip()
                    if key == "block_index":
                        block["index"] = int(val)
                    elif key == "data":
                        block["data"] = val
                    elif key == "previous_nonce" or key == "prev_nonce":
                        block["previous_nonce"] = val
                    elif key == "block_hash":
                        block["block_hash"] = val
            return block
        else:
            try:
                return json.loads(raw_content)
            except Exception as e:
                print(f"Error parsing JSON input: {e}")
                sys.exit(1)
    return None


def output_block(block: dict, json_out_path: str = None, txt_out_path: str = None):
    """Output block dictionary as JSON or plain text file / stdout."""
    if txt_out_path:
        txt_str = format_block_txt_str(block)
        if txt_out_path in ("-", "stdout"):
            print(txt_str, end="")
        else:
            save_block_to_txt(block, txt_out_path)
            print(f"Saved text block to: {txt_out_path}")
            
    if json_out_path:
        json_str = json.dumps(block, indent=2) + "\n"
        if json_out_path in ("-", "stdout"):
            print(json_str, end="")
        else:
            with open(json_out_path, "w", encoding="utf-8") as f:
                f.write(json_str)
            print(f"Saved JSON block to: {json_out_path}")
            
    if not txt_out_path and not json_out_path:
        # Default stdout: print JSON
        print(json.dumps(block, indent=2))


def cmd_genesis(args):
    """
    Generate Genesis Block #0 directly from secret seed.
    nonce_hash_0 = SHA-512(N_0) (calculated locally, NOT written to block)
    block_hash_0 = SHA-512(data_0 + nonce_hash_0)
    previous_nonce = "0x0"
    """
    seed_arg = getattr(args, "seed", None)
    data_arg = getattr(args, "data", None) or "Genesis Block"
    
    if not seed_arg:
        json_data = load_json_input(getattr(args, "json_file", None))
        if json_data:
            seed_arg = json_data.get("seed") or json_data.get("secret_seed")
            data_arg = json_data.get("data", data_arg)

    if not seed_arg:
        print("Error: Missing required 512-bit secret seed. Use -s/--seed <seed_or_file> or pass block.json")
        sys.exit(1)

    seed_val = load_seed_from_arg_or_file(seed_arg)
    
    start_time = time.perf_counter()
    prng = CryptoPRNG512(seed_val)
    
    # Private PRNG number N_0
    raw_N0 = prng.next_int()
    nonce_hash_0 = compute_nonce_hash(raw_N0)
    
    # block_hash = SHA-512(data_0 + nonce_hash_0)
    block_hash = compute_block_hash(data_arg, nonce_hash_0)
    
    elapsed_us = (time.perf_counter() - start_time) * 1_000_000
    
    genesis_block = {
        "index": 0,
        "data": data_arg,
        "previous_nonce": "0x0",
        "block_hash": block_hash,
        "time_to_know_nonce": f"{elapsed_us:.2f} µs (INSTANT)"
    }
    
    output_block(genesis_block, json_out_path=getattr(args, "out", None), txt_out_path=getattr(args, "txt_out", None))


def cmd_mint_block(args):
    """
    Mint the NEXT block (Block k+1) given the CURRENT block (Block k):
    - Reads current block index k (from fed block.json, block.txt, or stdin). Next index = k + 1.
    - Calculates `previous_nonce` for Block k+1 = SHA-512(N_k), revealing current block's nonce.
    - Calculates `block_hash` for Block k+1 = SHA-512(new_data + SHA-512(N_{k+1})).
    - Outputs the NEW NEXT BLOCK (Block k+1).
    """
    input_data = load_json_input(args.json_file)
    
    seed_arg = None
    new_data = None
    current_index = -1
    
    if input_data:
        if "index" in input_data:
            current_index = input_data["index"]
            
        seed_arg = input_data.get("seed") or input_data.get("secret_seed")
        new_data = input_data.get("next_data") or (input_data.get("data") if "index" not in input_data else None)
        
    if not seed_arg and getattr(args, "seed", None):
        seed_arg = args.seed
    if getattr(args, "data", None):
        new_data = args.data

    if not seed_arg or not new_data:
        print("Error: Missing required 'seed' or new block 'data'.")
        print("Usage: ./cli.py mint current_block.json -s <seed> -d <new_data>")
        sys.exit(1)

    seed_val = load_seed_from_arg_or_file(seed_arg)
    
    next_index = current_index + 1 if current_index >= 0 else 1
    current_step = next_index - 1  # step k for revealing N_k in block k+1
    
    start_time = time.perf_counter()
    prng = CryptoPRNG512(seed_val)
    
    # 1. Advance PRNG to step k to compute previous_nonce = SHA-512(N_k)
    for _ in range(current_step):
        prng.next_bytes()
        
    raw_N_curr = prng.next_int()
    previous_nonce_val = compute_nonce_hash(raw_N_curr)
    
    # 2. Advance PRNG to step k+1 to compute nonce_hash_{k+1} = SHA-512(N_{k+1})
    raw_N_next = prng.next_int()
    nonce_hash_next = compute_nonce_hash(raw_N_next)
    
    # 3. block_hash_{k+1} = SHA-512(new_data + nonce_hash_{k+1})
    next_block_hash = compute_block_hash(new_data, nonce_hash_next)
    
    elapsed_us = (time.perf_counter() - start_time) * 1_000_000
    
    next_block = {
        "index": next_index,
        "data": new_data,
        "previous_nonce": previous_nonce_val,
        "block_hash": next_block_hash,
        "time_to_know_nonce": f"{elapsed_us:.2f} µs (INSTANT)"
    }
    
    output_block(next_block, json_out_path=getattr(args, "out", None), txt_out_path=getattr(args, "txt_out", None))


def cmd_verify_block(args):
    """
    Verify block verification using formula: H(Data + Nonce) = BLOCK_HASH
    """
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
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    block = json.load(f)
            except Exception:
                pass

    if not block:
        print(f"Error: Could not parse block from '{filepath}'.")
        sys.exit(1)
        
    print("=" * 80)
    print(f"VERIFYING BLOCK #{block.get('index', 0)}")
    print("=" * 80)
    print(f"  Data                 : '{block.get('data')}'")
    print(f"  Previous Nonce       : {block.get('previous_nonce', '0x0')[:32]}...")
    print(f"  Block Hash           : {block.get('block_hash')[:32]}...\n")
    
    # If prev_file is provided, Block k (args.file) reveals the Nonce for Block k-1 (args.prev_file)
    if args.prev_file:
        if not os.path.exists(args.prev_file):
            print(f"Error: Target block file '{args.prev_file}' not found.")
            sys.exit(1)
            
        prev_block = parse_block_txt(args.prev_file) if not args.prev_file.endswith(".json") else json.load(open(args.prev_file))
        prev_data = prev_block.get('data', '')
        revealed_nonce = block.get('previous_nonce', '')
        target_block_hash = prev_block.get('block_hash', '')
        
        calc_hash = compute_block_hash(prev_data, revealed_nonce)
        
        print(f"VERIFYING BLOCK #{prev_block.get('index', 0)} VIA REVEALED NONCE IN BLOCK #{block.get('index', 0)}:")
        print("  H(Data + Nonce) = BLOCK_HASH")
        print(f"  H('{prev_data}' + {revealed_nonce[:16]}...) = {target_block_hash[:32]}...")
        
        if calc_hash == target_block_hash:
            print("\n✅ RESULT: H(Data + Nonce) = BLOCK_HASH (VALID)")
        else:
            print(f"\n❌ RESULT: INVALID! Calculated {calc_hash[:32]}... != {target_block_hash[:32]}...")
            sys.exit(1)
    else:
        print("  Formula: H(Data + Nonce) = BLOCK_HASH")
        print("  Note: Provide the subsequent block (-p / --prev-file) which reveals the Nonce to verify this block's hash.")


def cmd_parse_block(args):
    """Parse a block .txt or .json file and output to JSON or text."""
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

    output_block(block, json_out_path=getattr(args, "out", None), txt_out_path=getattr(args, "txt_out", None))


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
        
    target_hash_hex = block.get("previous_nonce")
    if not target_hash_hex or target_hash_hex == "0x0":
        print("Target block has no previous nonce hash.")
        sys.exit(1)
        
    print("=" * 80)
    print(f"OUTSIDER ATTACK SIMULATION (Targeting Block #{block.get('index', 0)})")
    print("=" * 80)
    print(f"Target Nonce Hash: {target_hash_hex}")
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
        description="512-Bit Secret Seed Sequential Blockchain Identity CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Command: gen-seed
    p_gen = subparsers.add_parser("gen-seed", help="Generate a 512-bit secret seed and public address")
    p_gen.add_argument("-o", "--out", help="File path to save secret seed or identity JSON")
    p_gen.add_argument("-j", "--json", action="store_true", help="Output identity as JSON")
    p_gen.set_defaults(func=cmd_gen_seed)
    
    # Command: genesis / gen-genesis / genesis-block
    for name in ["genesis", "gen-genesis", "genesis-block"]:
        p_gen_b = subparsers.add_parser(name, help="Generate the first block (Genesis Block #0) directly from a secret seed")
        p_gen_b.add_argument("json_file", nargs="?", default=None, help="Optional input block.json / block.txt or '-' for stdin")
        p_gen_b.add_argument("-s", "--seed", help="512-bit secret seed (hex string or file path)")
        p_gen_b.add_argument("-d", "--data", default="Genesis Block", help="Data message for genesis block")
        p_gen_b.add_argument("-o", "--out", help="Output JSON file path for genesis block")
        p_gen_b.add_argument("-t", "--txt-out", help="Output .txt file path or '-' for stdout text")
        p_gen_b.set_defaults(func=cmd_genesis)
    
    # Command: mint
    p_mint = subparsers.add_parser("mint", help="Mint next block by feeding current block (file or stdin)")
    p_mint.add_argument("json_file", nargs="?", default=None, help="Path to current block (.json/.txt) or '-' for stdin")
    p_mint.add_argument("-s", "--seed", help="512-bit secret seed (hex string or file path)")
    p_mint.add_argument("-d", "--data", help="Data / Transaction message for the NEW block")
    p_mint.add_argument("-o", "--out", help="Output JSON file path for NEW minted block")
    p_mint.add_argument("-t", "--txt-out", help="Output .txt file path or '-' for stdout text")
    p_mint.set_defaults(func=cmd_mint_block)
    
    # Command: verify
    p_verify = subparsers.add_parser("verify", help="Verify the integrity of a block file (.json or .txt)")
    p_verify.add_argument("file", help="Path to block file (.json or .txt)")
    p_verify.add_argument("-p", "--prev-file", help="Path to previous block file to verify chain link")
    p_verify.set_defaults(func=cmd_verify_block)
    
    # Command: parse_block & parse-block
    for name in ["parse_block", "parse-block"]:
        p_parse = subparsers.add_parser(name, help="Parse a block file into JSON format or text format")
        p_parse.add_argument("file", help="Input .txt or .json block file path")
        p_parse.add_argument("-o", "--out", help="Output JSON file path")
        p_parse.add_argument("-t", "--txt-out", help="Output .txt file path or '-' for stdout text")
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
