from cassandra.cluster import Cluster
from cassandra.query import SimpleStatement
import random
import string
import time
from uuid import uuid4

# Generate random name
def generate_name():
    first_names = ["Alice", "Bob", "Charlie", "David", "Emma", "Fiona", "Grace", "Hannah", "Isaac", "Julia"]
    last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez"]
    return f"{random.choice(first_names)} {random.choice(last_names)}"

# Generate random email
def generate_email(name):
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

# Connect to Cassandra
cluster = Cluster(['127.0.0.1'])
session = cluster.connect()

# Create keyspace and table
session.execute("""
    CREATE KEYSPACE IF NOT EXISTS encryptiondb
    WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 1}
""")
session.set_keyspace('encryptiondb')

session.execute("""
    CREATE TABLE IF NOT EXISTS unencrypted_users (
        id UUID PRIMARY KEY,
        name TEXT,
        email TEXT,
        credit_card TEXT
    )
""")

session.execute("""
  CREATE INDEX IF NOT EXISTS email_index ON unencrypted_users(email);
""")

# Generate 1000 records
sample_data = [
    (uuid4(), generate_name(), generate_email(generate_name()), generate_credit_card())
    for _ in range(1000)
]

# Measure insert time
insert_query = session.prepare("INSERT INTO unencrypted_users (id, name, email, credit_card) VALUES (?, ?, ?, ?)")
insert_time = measure_time(lambda: [session.execute(insert_query, record) for record in sample_data])

# Measure select time (fetch all records)
select_query = SimpleStatement("SELECT * FROM unencrypted_users")
select_time = measure_time(lambda: session.execute(select_query).all())

# Fetch all email records and filter by emails ending with @example.com
select_query_for_ids = SimpleStatement("SELECT id, email FROM unencrypted_users")
result = session.execute(select_query_for_ids)

# Filter out users with email ending with @example.com
emails_to_update = [row.id for row in result if row.email.endswith('@example.com')]

# Measure update time (update records matching a condition)
update_time = 0
updated_rows_count = 0
for user_id in emails_to_update:
    update_query = f"UPDATE unencrypted_users SET name = 'James David' WHERE id = {user_id}"
    update_time += measure_time(lambda: session.execute(update_query))
    updated_rows_count += 1

# Output times and the number of updated rows
print(f"Insert Time: {insert_time:.10f} seconds")
print(f"Select Time: {select_time:.10f} seconds")
print(f"Update Time: {update_time:.10f} seconds")
print(f"Rows Updated: {updated_rows_count}")

# Close the connection
cluster.shutdown()
