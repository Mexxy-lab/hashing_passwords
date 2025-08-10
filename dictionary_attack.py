#!/usr/bin/env python3
import hashlib
import sqlite3
import bcrypt  # type: ignore
import os
import time

BASEDIR = os.path.abspath(os.path.dirname(__file__))

def hash_password(password, algorithm='md5'):
    if algorithm == 'md5':
        return hashlib.md5(password.encode()).hexdigest()
    elif algorithm == 'sha1':
        return hashlib.sha1(password.encode()).hexdigest()
    elif algorithm == 'sha256':
        return hashlib.sha256(password.encode()).hexdigest()
    else:
        raise ValueError(f"Unsupported hashing algorithm for direct hashing: {algorithm}")

def dictionary_attack(db_name='passwords.db', dictionary_file='common_passwords.txt', verbose=True):
    db_path = os.path.join(BASEDIR, db_name)
    if not os.path.exists(db_path):
        print(f"[!] Database file not found at: {db_path}")
        return []

    if not os.path.exists(os.path.join(BASEDIR, dictionary_file)):
        print(f"[!] Dictionary file '{dictionary_file}' not found in {BASEDIR}.")
        return []

    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    c.execute("SELECT id, hashed_password, algorithm FROM hashed_password WHERE cracked = 0")
    uncracked_hashes = c.fetchall()

    if not uncracked_hashes:
        if verbose:
            print("[*] No uncracked hashes found in the database.")
        conn.close()
        return []

    if verbose:
        print(f"[*] Loaded {len(uncracked_hashes)} hash(es) to crack:")
        for r in uncracked_hashes:
            _id, h, alg = r
            print(f"    id={_id} alg={alg} hash_preview={h[:60]}{'...' if len(h)>60 else ''}")

    # Load dictionary
    with open(os.path.join(BASEDIR, dictionary_file), 'r', encoding='utf-8', errors='ignore') as f:
        passwords = [line.strip() for line in f if line.strip()]

    if verbose:
        print(f"[*] Loaded {len(passwords)} password(s) from dictionary.")

    cracked = []
    start = time.time()

    for _id, stored_hash, algorithm in uncracked_hashes:
        stored_hash = stored_hash.strip()
        if verbose:
            print(f"\n[*] Trying to crack id={_id} algorithm={algorithm} hash_preview={stored_hash[:60]}{'...' if len(stored_hash)>60 else ''}")

        if algorithm == 'bcrypt':
            if not (stored_hash.startswith('$2') or stored_hash.startswith('$argon') or stored_hash.startswith('$bcrypt')):
                if verbose:
                    print(f"[!] Warning: stored hash does not look like a bcrypt hash (prefix={stored_hash[:4]})")

            found = False
            for guess in passwords:
                try:
                    if bcrypt.checkpw(guess.encode(), stored_hash.encode()):
                        if verbose:
                            print(f"[+] bcrypt: Found match for id={_id}: '{guess}'")
                        c.execute("UPDATE hashed_password SET original_password = ?, cracked = 1 WHERE id = ?", (guess, _id))
                        conn.commit()
                        cracked.append({'id': _id, 'password': guess, 'hash': stored_hash, 'algorithm': algorithm})
                        found = True
                        break
                except Exception as e:
                    if verbose:
                        print(f"[!] bcrypt check error for id={_id}: {e}")
                    break
            if not found and verbose:
                print("[*] bcrypt: no match for this hash with the current dictionary.")

        elif algorithm in ('md5', 'sha1', 'sha256'):
            found = False
            for guess in passwords:
                try:
                    guessed_hash = hash_password(guess, algorithm)
                except ValueError:
                    if verbose:
                        print(f"[!] Unsupported algorithm: {algorithm}")
                    break

                if guessed_hash == stored_hash:
                    if verbose:
                        print(f"[+] {algorithm}: Found match for id={_id}: '{guess}' (hash={guessed_hash})")
                    c.execute("UPDATE hashed_password SET original_password = ?, cracked = 1 WHERE id = ?", (guess, _id))
                    conn.commit()
                    cracked.append({'id': _id, 'password': guess, 'hash': stored_hash, 'algorithm': algorithm})
                    found = True
                    break
            if not found and verbose:
                print(f"[*] {algorithm}: no match for this hash with the current dictionary.")
        else:
            if verbose:
                print(f"[!] Unsupported algorithm in DB: {algorithm}")

    conn.close()
    elapsed = time.time() - start
    if verbose:
        print(f"\n[*] Done. Found {len(cracked)} matches in {elapsed:.2f}s.")
    return cracked

if __name__ == '__main__':
    dictionary_attack()
