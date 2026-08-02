#!/usr/bin/env python3
"""
CLI Tool for 512-Bit Secret Seed Sequential Blockchain Identity & Instant Nonce Generator.
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
    SeedBlockchain,
    save_block_to_txt,
    parse_block_txt,
    save_chain_to_txt,
    parse_chain_txt,
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
            seed_input = f.read().strip()
    
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
    """Mint a new block using block.json input from file or stdin."""
    block_json_data = load_json_input(args.json_file)
    
    seed_arg = None
    data_arg = None
    ledger_path = args.ledger
    block_dir = args.block_dir
    
    if block_json_data:
        seed_arg = block_json_data.get("seed") or block_json_data.get("secret_seed")
        data_arg = block_json_data.get("data")
        ledger_path = block_json_data.get("ledger", ledger_path)
        block_dir = block_json_data.get("block_dir", block_dir)
        
    if not seed_arg and getattr(args, "seed", None):
        seed_arg = args.seed
    if not data_arg and getattr(args, "data", None):
        data_arg = args.data

    if not seed_arg or not data_arg:
        print("Error: Missing required 'seed' or 'data' in block JSON or arguments.")
        print("Expected block.json format: {\"seed\": \"<seed_or_key_file>\", \"data\": \"<transaction_data>\"}")
        sys.exit(1)

    seed_val = load_seed_from_arg_or_file(seed_arg)
    
    # Load existing ledger blocks if file exists
    existing_blocks = []
    if os.path.exists(ledger_path):
        existing_blocks = parse_chain_txt(ledger_path)
    
    block_index = len(existing_blocks)
    prev_hash = existing_blocks[-1]["block_hash"] if existing_blocks else "0" * 128
    
    # Initialize PRNG and advance to current step
    prng = CryptoPRNG512(seed_val)
    for _ in range(block_index):
        prng.next_bytes()
        
    start_time = time.perf_counter()
    nonce_curr = prng.next_int()
    h_curr = sha512_int(nonce_curr)
    
    block_content = (prev_hash + data_arg + h_curr.hex()).encode('utf-8')
    block_hash = sha512_bytes(block_content).hex()
    elapsed_us = (time.perf_counter() - start_time) * 1_000_000
    
    block = {
        "index": block_index,
        "data": data_arg,
        "nonce_N_i": hex(nonce_curr),
        "nonce_hash_H_Ni": h_curr.hex(),
        "prev_hash": prev_hash,
        "block_hash": block_hash,
        "time_to_know_nonce": f"{elapsed_us:.2f} µs (INSTANT)"
    }
    
    existing_blocks.append(block)
    
    # Save individual block text file
    os.makedirs(block_dir, exist_ok=True)
    block_file = os.path.join(block_dir, f"block_{block_index}.txt")
    save_block_to_txt(block, block_file)
    
    # Update ledger file
    save_chain_to_txt(existing_blocks, ledger_path)
    
    print("=" * 80)
    print(f"BLOCK #{block_index} MINTED SUCCESSFULLY")
    print("=" * 80)
    print(f"  Data               : '{block['data']}'")
    print(f"  Nonce N_{block_index} (512-bit) : {block['nonce_N_i'][:32]}...")
    print(f"  Nonce Commitment   : {block['nonce_hash_H_Ni'][:32]}...")
    print(f"  Block Hash         : {block['block_hash'][:32]}...")
    print(f"  Resolution Time    : {block['time_to_know_nonce']}")
    print(f"  Saved block file   : {block_file}")
    print(f"  Updated ledger file: {ledger_path}\n")


def cmd_verify_ledger(args):
    """Verify integrity of the text file ledger."""
    ledger_path = args.ledger
    if not os.path.exists(ledger_path):
        print(f"Error: Ledger file '{ledger_path}' not found.")
        sys.exit(1)
        
    blocks = parse_chain_txt(ledger_path)
    print("=" * 80)
    print(f"VERIFYING BLOCKCHAIN LEDGER ({len(blocks)} blocks)")
    print("=" * 80 + "\n")
    
    valid = True
    for i, block in enumerate(blocks):
        # 1. Verify previous hash link
        expected_prev = blocks[i - 1]["block_hash"] if i > 0 else "0" * 128
        if block["prev_hash"] != expected_prev:
            print(f"❌ Block #{i} INVALID PREVIOUS HASH LINK!")
            valid = False
            continue
            
        # 2. Verify nonce hash commitment
        nonce_int = int(block["nonce_N_i"], 16)
        calc_h_curr = sha512_int(nonce_int).hex()
        if calc_h_curr != block["nonce_hash_H_Ni"]:
            print(f"❌ Block #{i} INVALID NONCE COMMITMENT!")
            valid = False
            continue
            
        # 3. Verify block hash calculation
        block_content = (block["prev_hash"] + block["data"] + calc_h_curr).encode('utf-8')
        calc_block_hash = sha512_bytes(block_content).hex()
        if calc_block_hash != block["block_hash"]:
            print(f"❌ Block #{i} INVALID BLOCK HASH COMPUTATION!")
            valid = False
            continue
            
        print(f"✅ Block #{i} ('{block['data']}'): VALID")
        
    print("\n" + "=" * 80)
    if valid:
        print("RESULT: ALL BLOCKS IN LEDGER ARE CRYPTOGRAPHICALLY VALID ✅")
    else:
        print("RESULT: LEDGER CONTAINS CORRUPTED OR TAMPERED BLOCKS ❌")
    print("=" * 80 + "\n")


def cmd_show_ledger(args):
    """Display blocks stored in the text ledger."""
    ledger_path = args.ledger
    if not os.path.exists(ledger_path):
        print(f"Error: Ledger file '{ledger_path}' not found.")
        sys.exit(1)
        
    blocks = parse_chain_txt(ledger_path)
    print("=" * 80)
    print(f"BLOCKCHAIN LEDGER ({len(blocks)} BLOCKS)")
    print("=" * 80 + "\n")
    
    for block in blocks:
        print(f"--- Block #{block['index']} ---")
        print(f"  Data               : {block['data']}")
        print(f"  Prev Hash          : {block['prev_hash'][:32]}...")
        print(f"  Nonce N_{block['index']}            : {block['nonce_N_i'][:32]}...")
        print(f"  Nonce Hash H(N_{block['index']})   : {block['nonce_hash_H_Ni'][:32]}...")
        print(f"  Block Hash         : {block['block_hash'][:32]}...")
        print(f"  Mint Resolution    : {block['time_to_know_nonce']}\n")


def cmd_parse_block(args):
    """Parse a block or ledger text file and output to JSON or stdout."""
    filepath = args.file
    if not os.path.exists(filepath):
        print(f"Error: File '{filepath}' not found.")
        sys.exit(1)
        
    # Try parsing as combined ledger or single block file
    blocks = parse_chain_txt(filepath)
    if not blocks:
        block = parse_block_txt(filepath)
        if block:
            data_to_output = block
        else:
            print(f"Error: Could not parse block data from '{filepath}'.")
            sys.exit(1)
    elif len(blocks) == 1:
        data_to_output = blocks[0]
    else:
        data_to_output = blocks

    json_str = json.dumps(data_to_output, indent=2)
    
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(json_str + "\n")
        print(f"Successfully parsed '{filepath}' and saved JSON to '{args.out}'")
    else:
        print(json_str)


def cmd_attack_sim(args):
    """Simulate an attacker attempting to brute-force a block nonce without the seed."""
    ledger_path = args.ledger
    if not os.path.exists(ledger_path):
        print(f"Error: Ledger file '{ledger_path}' not found.")
        sys.exit(1)
        
    blocks = parse_chain_txt(ledger_path)
    if not blocks:
        print("Ledger is empty.")
        sys.exit(1)
        
    block_idx = min(args.block_index, len(blocks) - 1)
    target_block = blocks[block_idx]
    target_hash_hex = target_block["nonce_hash_H_Ni"]
    
    print("=" * 80)
    print(f"OUTSIDER ATTACK SIMULATION (Targeting Block #{block_idx})")
    print("=" * 80)
    print(f"Target Nonce Commitment H(N_{block_idx}): {target_hash_hex}")
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
        description="512-Bit Secret Seed Blockchain & Instant Nonce CLI Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Command: gen-seed
    p_gen = subparsers.add_parser("gen-seed", help="Generate a 512-bit secret seed and public address")
    p_gen.add_argument("-o", "--out", help="File path to save the secret seed (e.g., secret.key)")
    p_gen.set_defaults(func=cmd_gen_seed)
    
    # Command: mint
    p_mint = subparsers.add_parser("mint", help="Mint a new block using block.json input from file or stdin")
    p_mint.add_argument("json_file", nargs="?", default=None, help="Path to block.json file or '-' for stdin")
    p_mint.add_argument("-s", "--seed", help="512-bit secret seed (hex string or file path)")
    p_mint.add_argument("-d", "--data", help="Data / Transaction message for the block")
    p_mint.add_argument("-l", "--ledger", default="blockchain_ledger.txt", help="Path to ledger text file")
    p_mint.add_argument("-b", "--block-dir", default="blocks", help="Directory to save individual block .txt files")
    p_mint.set_defaults(func=cmd_mint_block)
    
    # Command: verify
    p_verify = subparsers.add_parser("verify", help="Verify the integrity of a text ledger file")
    p_verify.add_argument("-l", "--ledger", default="blockchain_ledger.txt", help="Path to ledger text file")
    p_verify.set_defaults(func=cmd_verify_ledger)
    
    # Command: show
    p_show = subparsers.add_parser("show", help="Display all blocks in the text ledger")
    p_show.add_argument("-l", "--ledger", default="blockchain_ledger.txt", help="Path to ledger text file")
    p_show.set_defaults(func=cmd_show_ledger)
    
    # Command: parse_block & parse-block
    for name in ["parse_block", "parse-block"]:
        p_parse = subparsers.add_parser(name, help="Parse a block or ledger .txt file into JSON format")
        p_parse.add_argument("file", help="Input .txt block or ledger file path")
        p_parse.add_argument("-o", "--out", help="Output JSON file path (e.g., block.json)")
        p_parse.set_defaults(func=cmd_parse_block)
    
    # Command: attack
    p_attack = subparsers.add_parser("attack", help="Simulate brute-force attack on a block nonce without seed")
    p_attack.add_argument("-i", "--block-index", type=int, default=0, help="Index of block to attack")
    p_attack.add_argument("-a", "--attempts", type=int, default=100000, help="Number of brute-force attempts")
    p_attack.add_argument("-l", "--ledger", default="blockchain_ledger.txt", help="Path to ledger text file")
    p_attack.set_defaults(func=cmd_attack_sim)
    
    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        sys.exit(1)
        
    args.func(args)


if __name__ == "__main__":
    main()
