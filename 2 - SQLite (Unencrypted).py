import sqlite3
import random
import string
import time

# Generate random name
def generate_name():
    first_names = ["Alice", "Bob", "Charlie", "David", "Emma", "Fiona", "Grace", "Hannah", "Isaac", "Julia"]
    last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez"]
    return f"{random.choice(first_names)} {random.choice(last_names)}"

# Generate random email
def generate_email():
    domains = ["example.com", "test.com", "mail.com", "demo.com", "sample.org"]
    username = "".join(random.choices(string.ascii_lowercase, k=5))
    return f"{username}@{random.choice(domains)}"

# Generate random credit card number
def generate_credit_card():
    return "-".join(["".join(random.choices(string.digits, k=4)) for _ in range(4)])

# Measure operation time
def measure_time(func, *args):
    start_time = time.time()
    func(*args)
    end_time = time.time()
    return end_time - start_time

# SQLite operations
def sqlite_operations():
    connection = sqlite3.connect("EncryptionDB.sqlite")
    cursor = connection.cursor()

    # Create table
    cursor.execute("DROP TABLE IF EXISTS unencrypted_users")
    cursor.execute("""
        CREATE TABLE unencrypted_users (
            ID INTEGER PRIMARY KEY AUTOINCREMENT,
            Name TEXT,
            Email TEXT,
            CreditCard TEXT
        )
    """)

    # Generate 1000 records
    records = [
        (generate_name(), generate_email(), generate_credit_card())
        for _ in range(1000)
    ]

    # Insert records
    insert_time = measure_time(
        cursor.executemany,
        "INSERT INTO unencrypted_users (Name, Email, CreditCard) VALUES (?, ?, ?)",
        records
    )
    connection.commit()

    # Select records
    select_time = measure_time(cursor.execute, "SELECT * FROM unencrypted_users")
    cursor.fetchall()

    # Update records
    update_time = measure_time(cursor.execute, "UPDATE unencrypted_users SET Name = 'James David' WHERE Email LIKE '%@example.com'")
    connection.commit()

    # Get the number of updated rows
    updated_records = cursor.rowcount

    connection.close()

    print(f"Insert Time: {insert_time:.10f} seconds")
    print(f"Select Time: {select_time:.10f} seconds")
    print(f"Update Time: {update_time:.10f} seconds")
    print(f"Number of records updated: {updated_records}")

# Run SQLite operations
sqlite_operations()
