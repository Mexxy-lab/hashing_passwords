from flask import Flask, request, jsonify # type: ignore
from flask_sqlalchemy import SQLAlchemy # type: ignore
from flask import render_template # type: ignore
import hashlib
import sqlite3
import os
import bcrypt # type: ignore
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
basedir = os.path.abspath(os.path.dirname(__file__))
BASEDIR = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'passwords.db')
db = SQLAlchemy(app)

class HashedPassword(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_password = db.Column(db.String(150))
    hashed_password = db.Column(db.String(150), unique=True)
    algorithm = db.Column(db.String(50))
    cracked = db.Column(db.Boolean, default=False)

def hash_password(password, algorithm='md5'):
    if algorithm == 'md5':
        return hashlib.md5(password.encode()).hexdigest()
    elif algorithm == 'sha1':
        return hashlib.sha1(password.encode()).hexdigest()
    elif algorithm == 'sha256':
        return hashlib.sha256(password.encode()).hexdigest()
    elif algorithm == 'bcrypt':
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode(), salt)
        return hashed.decode('utf-8')
    else:
        raise ValueError(f"Unsupported hashing algorithm: {algorithm}")

def insert_passwords_from_file(password_file='passwords.txt'):
    if not os.path.exists(password_file):
        print(f"[!] File '{password_file}' not found.")
        return

    with open(password_file, 'r') as file:
        for line in file:
            password = line.strip()
            for algorithm in ['md5', 'sha1', 'sha256', 'bcrypt']:
                hashed = hash_password(password, algorithm)
                existing = HashedPassword.query.filter_by(hashed_password=hashed).first()
                if not existing:
                    db.session.add(HashedPassword(
                        original_password=password,
                        hashed_password=hashed,
                        algorithm=algorithm
                    ))
                    try:
                        db.session.commit()
                        print(f"[+] Inserted password '{password}' hashed with {algorithm}")
                    except Exception as e:
                        db.session.rollback()
                        print(f"[!] Error inserting '{password}': {e}")
                else:
                    print(f"[-] Skipped duplicate for hash {hashed}")

def insert_hashes_from_file(hash_file='hashes.txt'):
    if not os.path.exists(hash_file):
        print(f"[!] File '{hash_file}' not found.")
        return

    with open(hash_file, 'r') as file:
        for line in file:
            parts = line.strip().split(':', 1)
            if len(parts) != 2:
                print(f"[!] Invalid line in {hash_file}: {line.strip()}")
                continue
            algorithm, hash_value = parts
            algorithm = algorithm.lower()
            if algorithm not in ['md5', 'sha1', 'sha256', 'bcrypt']:
                print(f"[!] Unsupported algorithm: {algorithm}")
                continue

            existing = HashedPassword.query.filter_by(hashed_password=hash_value).first()
            if not existing:
                db.session.add(HashedPassword(
                    original_password=None,
                    hashed_password=hash_value,
                    algorithm=algorithm
                ))
                try:
                    db.session.commit()
                    print(f"[+] Inserted hash {hash_value} with algorithm {algorithm}")
                except Exception as e:
                    db.session.rollback()
                    print(f"[!] Error inserting hash {hash_value}: {e}")
            else:
                print(f"[-] Skipped duplicate hash: {hash_value}")

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

@app.route('/')
def home():
    return "Welcome to the Hashed Password Cracker!"

@app.route('/test')
def test():
    return "This is a test route."

@app.route('/crack-page')
def crack_page():
    return render_template('crack_all.html')

@app.route('/crack-all')
def crack_all():
    results = dictionary_attack()
    if isinstance(results, dict) and 'error' in results:
        return jsonify(results), 500

    if not results:
        return jsonify({
            'success': True,
            'message': 'No hashes were cracked (maybe all were already cracked or no matches).'
        })

    return jsonify({
        'success': True,
        'cracked': results
    })

@app.route('/history')
def history():
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute("SELECT hashed_password, original_password, algorithm FROM hashed_password WHERE cracked = 1")
    cracked_hashes = c.fetchall()
    conn.close()

    return render_template('history.html', cracked=cracked_hashes)

if __name__ == '__main__':
    if os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
        with app.app_context():
            db.drop_all()
            db.create_all()
            insert_passwords_from_file()  
            insert_hashes_from_file()
    app.run(debug=True)
