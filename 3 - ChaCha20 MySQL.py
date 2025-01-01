import time
import pymysql
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64
import random
import string

def generate_strong_key():
    """Generates a cryptographically secure random 32-byte (256-bit) key for ChaCha20."""
    return os.urandom(32)

def generate_nonce():
    """Generates a random 16-byte nonce for ChaCha20."""
    return os.urandom(16)  # Ensure 16 bytes for ChaCha20

key = generate_strong_key()
key_hex = key.hex()
print(f"Generated Key (Hex): {key_hex}")

key_bytes = bytes.fromhex(key_hex)

os.environ["ENCRYPTION_KEY"] = key_hex
print(os.environ.get("ENCRYPTION_KEY"))


def encrypt_data(data):
    """Encrypt data using ChaCha20 and Base64 encode."""
    nonce = generate_nonce()
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(data.encode()) + encryptor.finalize()
    encoded_data = base64.b64encode(nonce + encrypted).decode('utf-8')
    return encoded_data

def decrypt_data(encoded_data):
    """Decrypt Base64 encoded data using ChaCha20."""
    decoded_data = base64.b64decode(encoded_data.encode('utf-8'))
    nonce = decoded_data[:16]
    encrypted_data = decoded_data[16:]

    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted.decode()


def generate_name():
    first_names = ["Alice", "Bob", "Charlie", "David", "Emma", "Fiona", "Grace", "Hannah", "Isaac", "Julia"]
    last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez"]
    return f"{random.choice(first_names)} {random.choice(last_names)}"

def generate_email():
    domains = ["example.com", "test.com", "mail.com", "demo.com", "sample.org"]
    username = "".join(random.choices(string.ascii_lowercase, k=5))
    return f"{username}@{random.choice(domains)}"

def generate_credit_card():
    return "-".join(["".join(random.choices(string.digits, k=4)) for _ in range(4)])

def measure_time(func, *args):
    start_time = time.time()
    func(*args)
    end_time = time.time()
    return end_time - start_time

def mysql_operations():
    try:
        connection = pymysql.connect(host='127.0.0.1', user='root', password='W7301@jqir#', database='encryptiondb')
        cursor = connection.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                ID INT AUTO_INCREMENT PRIMARY KEY,
                Name VARCHAR(255),
                Email VARCHAR(255),
                CreditCard VARCHAR(255)
            );
        """)
        connection.commit()

        cursor.execute("ALTER TABLE users AUTO_INCREMENT = 1")
        connection.commit()

        cursor.execute("SELECT COUNT(*) FROM users")
        result = cursor.fetchone()
        row_count = result[0]

        if row_count == 0:
            records = [
                (generate_name(), encrypt_data(generate_email()), encrypt_data(generate_credit_card()))
                for _ in range(1000)
            ]
            insert_time = measure_time(
                cursor.executemany,
                "INSERT INTO users (Name, Email, CreditCard) VALUES (%s, %s, %s)", records
            )
            connection.commit()
            print(f"Insert Time: {insert_time:.10f} seconds")
        else:
            print("Table is not empty, skipping insertion")

        select_time = measure_time(cursor.execute, "SELECT * FROM users")
        print(f"Select Time: {select_time:.10f} seconds")

        cursor.execute("SELECT ID, Email FROM users")
        email_rows = cursor.fetchall()

        ids_to_update = []
        for row in email_rows:
            try:
                decrypted_email = decrypt_data(row[1])
                if decrypted_email.endswith("@example.com"):
                    ids_to_update.append(row[0])
            except (ValueError, TypeError, base64.binascii.Error) as e:
                print(f"Decryption error for ID {row[0]}: {e}")

        if ids_to_update:
            placeholders = ", ".join(["%s"] * len(ids_to_update))
            update_query = f"UPDATE users SET Name = 'James David' WHERE ID IN ({placeholders})"
            update_time = measure_time(cursor.execute, update_query, tuple(ids_to_update))
            connection.commit()
            print(f"Updated {len(ids_to_update)} records. Update Time: {update_time:.10f} seconds")
        else:
            print("No emails found ending with @example.com")

        cursor.execute("SELECT ID, Name, Email, CreditCard FROM users")
        results = cursor.fetchall()
        for row in results:
            if len(row) != 4:
                print(f"Warning: Row has missing data (length: {len(row)})")
                continue

            encrypted_email = row[2]
            encrypted_credit_card = row[3]
            try:
                decrypted_email = decrypt_data(encrypted_email)
                decrypted_credit_card = decrypt_data(encrypted_credit_card)
                print(
                    f"ID: {row[0]}, Name: {row[1]}, Decrypted Email: {decrypted_email}, Decrypted Credit Card: {decrypted_credit_card}")
            except (ValueError, TypeError, base64.binascii.Error) as e:
                print(f"Decryption Error for row {row[0]}: {e}")
                print(f"Encrypted Email: {encrypted_email}")
                print(f"Encrypted Credit Card: {encrypted_credit_card}")
                continue

    except pymysql.Error as e:
        print(f"MySQL Error: {e}")
    finally:
        if connection:
            connection.close()

mysql_operations()
