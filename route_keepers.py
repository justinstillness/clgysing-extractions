#!/usr/bin/env python3
"""
route_keepers.py — Route 33 keeper files from _untagged/ to NLMINTA staging dirs.

Classifies by Notebook ID:
  1e03c6b6... (SP03 Repositories)     → NLMINTA/clgysing/phase2/_pre-branch/SP03/
  cce3b796... (CLGYSING Source Pkgs)   → NLMINTA/clgysing/phase2/_pre-branch/CLGYSING-SP/

Run from the clgysing-extractions repo root on EC2.
Usage: python3 route_keepers.py [--dry-run]
"""

import os
import sys
import re
import subprocess

REPO_ROOT = "/home/ubuntu/clgysing-extractions"
UNTAGGED = os.path.join(REPO_ROOT, "_untagged")

# Routing map: notebook ID prefix → destination directory
ROUTES = {
    "1e03c6b6": "NLMINTA/clgysing/phase2/_pre-branch/SP03",
    "cce3b796": "NLMINTA/clgysing/phase2/_pre-branch/CLGYSING-SP",
}

def extract_notebook_id(filepath):
    """Extract Notebook ID from file header."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read(2000)  # Header is in first ~2000 chars
        match = re.search(r'Notebook ID:\s*([a-f0-9-]+)', content)
        if match:
            return match.group(1)
    except Exception as e:
        print(f"  ERROR reading {filepath}: {e}")
    return None

def main():
    dry_run = "--dry-run" in sys.argv
    
    if dry_run:
        print("=== DRY RUN MODE — no files will be moved ===\n")
    
    os.chdir(REPO_ROOT)
    
    # Get all files in _untagged/
    if not os.path.isdir(UNTAGGED):
        print(f"ERROR: {UNTAGGED} not found")
        sys.exit(1)
    
    files = sorted([f for f in os.listdir(UNTAGGED) if f.endswith('.txt') and f != '.gitkeep'])
    print(f"Found {len(files)} files in _untagged/\n")
    
    # Classify files
    classified = {"SP03": [], "CLGYSING-SP": [], "UNKNOWN": []}
    
    for fname in files:
        fpath = os.path.join(UNTAGGED, fname)
        nb_id = extract_notebook_id(fpath)
        
        if nb_id is None:
            classified["UNKNOWN"].append(fname)
            print(f"  UNKNOWN (no NB ID): {fname}")
            continue
        
        # Match against route prefixes
        routed = False
        for prefix, dest in ROUTES.items():
            if nb_id.startswith(prefix):
                if prefix == "1e03c6b6":
                    classified["SP03"].append(fname)
                else:
                    classified["CLGYSING-SP"].append(fname)
                routed = True
                break
        
        if not routed:
            classified["UNKNOWN"].append(fname)
            print(f"  UNKNOWN (NB ID: {nb_id}): {fname}")
    
    # Summary
    print(f"\n{'='*60}")
    print(f"CLASSIFICATION SUMMARY")
    print(f"{'='*60}")
    print(f"  SP03 Repositories:     {len(classified['SP03'])} files")
    print(f"  CLGYSING Source Pkgs:  {len(classified['CLGYSING-SP'])} files")
    print(f"  UNKNOWN:               {len(classified['UNKNOWN'])} files")
    print(f"  TOTAL:                 {len(files)} files")
    
    if classified["UNKNOWN"]:
        print(f"\n  WARNING: {len(classified['UNKNOWN'])} files could not be classified.")
        print(f"  These will remain in _untagged/.")
    
    if dry_run:
        print(f"\n=== DRY RUN COMPLETE — rerun without --dry-run to execute ===")
        return
    
    # Confirm
    proceed = input(f"\nProceed with moving {len(classified['SP03']) + len(classified['CLGYSING-SP'])} files? (yes/no): ")
    if proceed.strip().lower() != "yes":
        print("Aborted.")
        return
    
    # Create destination directories
    for dest in ROUTES.values():
        dest_path = os.path.join(REPO_ROOT, dest)
        os.makedirs(dest_path, exist_ok=True)
    
    # Move files using git mv
    moved = 0
    errors = 0
    
    for prefix, dest in ROUTES.items():
        if prefix == "1e03c6b6":
            file_list = classified["SP03"]
        else:
            file_list = classified["CLGYSING-SP"]
        
        for fname in file_list:
            src = os.path.join("_untagged", fname)
            dst = os.path.join(dest, fname)
            try:
                subprocess.run(["git", "mv", src, dst], check=True, capture_output=True)
                moved += 1
                print(f"  Moved: {fname} → {dest}/")
            except subprocess.CalledProcessError as e:
                errors += 1
                print(f"  ERROR moving {fname}: {e.stderr.decode()}")
    
    print(f"\n{'='*60}")
    print(f"MOVE COMPLETE: {moved} moved, {errors} errors")
    print(f"{'='*60}")
    
    if moved > 0:
        # Commit
        msg = f"Route {moved} keeper files from _untagged/ to NLMINTA staging dirs"
        subprocess.run(["git", "add", "-A"], check=True)
        subprocess.run(["git", "commit", "-m", msg], check=True)
        print(f"\nCommitted: {msg}")
        
        # Push
        push = input("Push to GitHub? (yes/no): ")
        if push.strip().lower() == "yes":
            subprocess.run(["git", "push"], check=True)
            print("Pushed successfully.")
        else:
            print("Not pushed. Run 'git push' manually when ready.")

if __name__ == "__main__":
    main()
