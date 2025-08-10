## Project Scope 

This project will guide students through 

- Creating a simple web application that hashes passwords, 

- Stores them in a database, and 

- Demonstrates how a dictionary attack can be used to crack these hashes.

## Environment Set up 

```bash 
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt 
```

## Implement Password Hashing and Storage using Flask and SQLAlchemy

- Demonstrates how to hash passwords and store them securely in a Database.

- Flask and SQLAlchemy: Flask is used to create the web application, and SQLAlchemy is used for interacting with the database.

- Database Model: HashedPassword class is a model representing the table where hashed passwords are stored.

- Routes: The routes / and /test demonstrate basic web application functionality.

- Password Hashing: The hash_password function demonstrates hashing using di􀆯erent algorithms (md5, sha1, sha256).

    - md5 algorithm 

## Implementing a Dictionary Attack

- A dictionary attack tries to crack hashed passwords by comparing them with hashes of common passwords.

- Hashing: The hash_password function hashes passwords using the same method as in app.py.

- Database Interaction: The script queries the database for unhashed passwords and compares them against a dictionary of common passwords.

- Dictionary Attack: It simulates how attackers might try to crack weak passwords by comparing them against a list of common passwords.

## Run the Dictionary Attack Script:

```bash
python app.py
python dictionary_attack.py
```
- This will:

    - Create the SQLite database (passwords.db)
    - Insert a few pre-defined hashed passwords
    - Launches the web server

## Improvements to application 

- Added additional algorithm bcrypt to the application 

- Created a mini web interface for the dictionary attack section so it outputs the cracked hashes 

- Added a history page to view all previously cracked password or hashes for easy troubleshooting. 

- Made sure all password or hashes are read from a file and not hardcoded in the application. 

- Password files are added to gitignore file and not tracked by git. 