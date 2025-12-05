import hashlib
import json
import sys
import os

def compute_hashes(filepath):
    with open(filepath, "rb") as f:
        data = f.read()

    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest()
    }

def save_hashes(hashes, output_file):
    with open(output_file, "w") as f:
        json.dump(hashes, f, indent=4)

def load_hashes(json_file):
    with open(json_file, "r") as f:
        return json.load(f)

def integrity_check(original_hashes, new_hashes):
    if original_hashes == new_hashes:
        print("Integrity check: PASS — file has NOT been tampered.")
    else:
        print("Integrity check: FAIL — file has been TAMPERED!")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python hash_util.py generate <file>")
        print("  python hash_util.py check <file> <hashes.json>")
        sys.exit(1)

    mode = sys.argv[1]

    if mode == "generate":
        file = sys.argv[2]
        hashes = compute_hashes(file)
        save_hashes(hashes, "hashes.json")
        print("Hashes saved to hashes.json")
        print(hashes)

    elif mode == "check":
        file = sys.argv[2]
        json_file = sys.argv[3]

        original_hashes = load_hashes(json_file)
        new_hashes = compute_hashes(file)

        integrity_check(original_hashes, new_hashes)