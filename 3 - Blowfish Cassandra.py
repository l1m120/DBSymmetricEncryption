import random
import string
import time
import base64
import uuid
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from cassandra.cluster import Cluster
from cassandra.query import BatchStatement, BatchType
import os

def generate_strong_key():
    """Generates a cryptographically secure random 56-byte key (448 bits) for Blowfish."""
    return get_random_bytes(56)  # 448 bits = 56 bytes

key = generate_strong_key()
key_hex = key.hex()
print(f"Generated Key (Hex): {key_hex}")

key_bytes = bytes.fromhex(key_hex)

os.environ["ENCRYPTION_KEY"] = key_hex
print(os.environ.get("ENCRYPTION_KEY"))

iv = get_random_bytes(8)

def encrypt_data(data):
    """Encrypt data using Blowfish with CBC mode and Base64 encode."""
    cipher = Blowfish.new(key_bytes, Blowfish.MODE_CBC, iv)
    padded_data = pad(data.encode(), Blowfish.block_size)
    encrypted = cipher.encrypt(padded_data)
    encoded_data = base64.b64encode(encrypted).decode('utf-8')
    return encoded_data

def decrypt_data(encoded_data):
    """Decrypt Base64 encoded data using Blowfish CBC mode."""
    decoded_data = base64.b64decode(encoded_data.encode('utf-8'))
    cipher = Blowfish.new(key_bytes, Blowfish.MODE_CBC, iv)
    decrypted_padded = unpad(cipher.decrypt(decoded_data), Blowfish.block_size)
    return decrypted_padded.decode()

def generate_name():
    first_names = ["Alice", "Bob", "Charlie", "David", "Emma", "Fiona", "Grace", "Hannah", "Isaac", "Julia"]
    last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez",
                  "Martinez"]
    return f"{random.choice(first_names)} {random.choice(last_names)}"

def generate_email():
    domains = ["example.com", "test.com", "mail.com", "demo.com", "sample.org"]
    username = "".join(random.choices(string.ascii_lowercase, k=5))
    return f"{username}@{random.choice(domains)}"

def generate_credit_card():
    return "-".join(["".join(random.choices(string.digits, k=4)) for _ in range(4)])

def measure_time(func, *args):
    start_time = time.time()
    result = func(*args)
    end_time = time.time()
    return end_time - start_time, result

def cassandra_operations():
    try:
        # Replace with your Cassandra details (localhost assumed)
        cloud_config = None  # No cloud configuration needed
        contact_point = "127.0.0.1"  # Replace with your Cassandra host if different
        keyspace = "encryptiondb"  # Replace with your keyspace name

        cluster = Cluster([contact_point])  # Connect to single contact point
        session = cluster.connect(keyspace)

        # Create table (if it doesn't exist)
        query = """
        CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY,
            name text,
            email text,
            creditcard text
        );
        """
        session.execute(query)

        # Check if table is empty
        query = "SELECT COUNT(*) FROM users"
        result = session.execute(query)
        row_count = result.one()[0]

        if row_count == 0:
            batch = BatchStatement(batch_type=BatchType.UNLOGGED)
            start_time = time.time()  # Start time for the insertion process
            for i in range(1000):
                user_id = uuid.uuid4()  # Generate a unique UUID
                query = "INSERT INTO users (id, name, email, creditcard) VALUES (%s, %s, %s, %s)"
                batch.add(query, (
                user_id, generate_name(), encrypt_data(generate_email()), encrypt_data(generate_credit_card())))

                # Insert in batches, say 100 records per batch
                if (i + 1) % 100 == 0 or (i + 1) == 1000:
                    session.execute(batch)
                    batch.clear()  # Clear the batch after executing
            end_time = time.time()  # End time after the entire process
            total_insert_time = end_time - start_time  # Calculate total time taken
            print(f"Total Insert Time for 1000 records: {total_insert_time:.10f} seconds")
        else:
            print("Table is not empty, skipping insertion")

        select_time, _ = measure_time(session.execute, "SELECT * FROM users")
        print(f"Select Time: {select_time:.10f} seconds")

        # Update users with email ending in "@example.com" (Decrypt in Python)
        query = "SELECT id, email FROM users"
        email_rows = session.execute(query)

        ids_to_update = []
        for row in email_rows:
            try:
                decrypted_email = decrypt_data(row.email)
                if decrypted_email.endswith("@example.com"):
                    ids_to_update.append(row.id)
            except (ValueError, TypeError, base64.binascii.Error) as e:
                print(f"Decryption error for ID {row.id}: {e}")

        if ids_to_update:
            batch = BatchStatement(batch_type=BatchType.UNLOGGED)
            for user_id in ids_to_update:
                query = "UPDATE users SET name = %s WHERE id = %s"
                batch.add(query, ("James David", user_id))
            update_time, _ = measure_time(session.execute, batch)
            print(f"Updated {len(ids_to_update)} records. Update Time: {update_time:.10f} seconds")

        else:
            print("No emails found ending with @example.com")

        # Demonstrate Decryption (limited to 5)
        query = "SELECT id, name, email, creditcard FROM users LIMIT 5"
        rows = session.execute(query)
        for row in rows:
            try:
                decrypted_email = decrypt_data(row.email)
                decrypted_credit_card = decrypt_data(row.creditcard)
                print(f"ID: {row.id}, Name: {row.name}, Decrypted Email: {decrypted_email}, Decrypted Credit Card: {decrypted_credit_card}")
            except (ValueError, TypeError, base64.binascii.Error) as e:
                print(f"Decryption Error for ID {row.id}: {e}")
                print(f"Encrypted Email: {row.email}")
                print(f"Encrypted Credit Card: {row.creditcard}")
                continue

    except Exception as e:
        print(f"Cassandra Error: {e}")
    finally:
        if session:
            session.shutdown()
        if cluster:
            cluster.shutdown()


import secrets
key = secrets.token_bytes(56)  # Use 56-byte key for Blowfish (448 bits)
key_hex = key.hex()
os.environ["ENCRYPTION_KEY"] = key_hex
print(f"Generated Key (Hex): {key_hex}")

cassandra_operations()
