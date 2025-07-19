import hashlib
import os
import sys
from datetime import datetime

# Get all files from the directory recursively
def get_file_list(directory):
    file_list = []
    for root, dirs, files in os.walk(directory):
        for f in files:
            path = os.path.join(root, f)
            file_list.append(path)
    return file_list

# Compute SHA-512 hash of a file
def compute_hash(filepath):
    sha512 = hashlib.sha512()
    try:
        with open(filepath, "rb") as f:
            while True:
                data = f.read(4096)
                if not data:
                    break
                sha512.update(data)
        return sha512.hexdigest()
    except Exception as e:
        print(f"⚠ Error reading {filepath}: {e}")
        return None

# Create baseline file with hashes
def create_baseline(directory, output_file):
    files = get_file_list(directory)
    with open(output_file, "w", encoding="utf-8") as out:
        for f in files:
            h = compute_hash(f)
            if h:
                out.write(f"{os.path.basename(f)}:{h}:{f}\n")
    print(f"✅ Baseline saved to {output_file}")

# Load existing baseline
def load_baseline(control_file):
    baseline = {}
    with open(control_file, "r", encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split(":")
            if len(parts) >= 3:
                filename, file_hash, filepath = parts[0], parts[1], parts[2]
                baseline[filename] = (file_hash, filepath)
    return baseline

# Check current files against baseline
def check_integrity(current_dir, control_file):
    saved = load_baseline(control_file)
    current_files = get_file_list(current_dir)
    current_hashes = {}
    for f in current_files:
        h = compute_hash(f)
        if h:
            current_hashes[os.path.basename(f)] = (h, f)

    added = [f for f in current_hashes if f not in saved]
    removed = [f for f in saved if f not in current_hashes]

    modified = []
    for f in current_hashes:
        if f in saved and current_hashes[f][0] != saved[f][0]:
            modified.append(f)

    print("\n🔍 File Integrity Scan Results:")
    if not any([added, removed, modified]):
        print("✅ All files are intact.")
    else:
        if added:
            print("\n➕ Added Files:")
            for f in added:
                print(f" - {f}")
        if removed:
            print("\n➖ Removed Files:")
            for f in removed:
                print(f" - {f}")
        if modified:
            print("\n🔄 Modified Files:")
            for f in modified:
                path = current_hashes[f][1]
                mod_time = datetime.fromtimestamp(os.path.getmtime(path)).strftime('%Y-%m-%d %H:%M:%S')
                print(f" - {f} (Last Modified: {mod_time})")

# Update existing baseline file
def update_baseline(directory, control_file):
    files = get_file_list(directory)
    with open(control_file, "w", encoding="utf-8") as out:
        for f in files:
            h = compute_hash(f)
            if h:
                out.write(f"{os.path.basename(f)}:{h}:{f}\n")
    print(f"🔄 Baseline updated successfully at {control_file}")

# Entry point
def main():
    print("🛡 File Integrity Checker")
    print("1. Create Baseline")
    print("2. Check Integrity")
    print("3. Update Baseline")
    choice = input("Choose an option: ").strip()

    if choice == "1":
        directory = input("Enter directory to scan: ").strip()
        output = input("Enter name for baseline file (e.g., control.txt): ").strip()
        create_baseline(directory, output)

    elif choice == "2":
        directory = input("Enter directory to scan: ").strip()
        control_file = input("Enter baseline file: ").strip()
        check_integrity(directory, control_file)

    elif choice == "3":
        directory = input("Enter directory to update baseline for: ").strip()
        control_file = input("Enter baseline file to update: ").strip()
        update_baseline(directory, control_file)

    else:
        print("❌ Invalid choice.")

if __name__ == "__main__":
    main()
