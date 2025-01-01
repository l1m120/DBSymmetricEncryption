import pymysql
import random
import string
import time

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

# Connect to MySQL
connection = pymysql.connect(
    host='localhost', user='root', password='W7301@jqir#', database='encryptiondb'
)
cursor = connection.cursor()

# Create table if not exists
cursor.execute("""
    CREATE TABLE IF NOT EXISTS unencrypted_users (
        ID INT AUTO_INCREMENT PRIMARY KEY,
        Name VARCHAR(255),
        Email VARCHAR(255),
        CreditCard VARCHAR(255)
    )
""")

# Measure insert time
sample_data = [(generate_name(), generate_email(generate_name()), generate_credit_card()) for _ in range(1000)]
start_time = time.time()
cursor.executemany("INSERT INTO unencrypted_users (Name, Email, CreditCard) VALUES (%s, %s, %s)", sample_data)
connection.commit()
insert_time = time.time() - start_time
print(f"Insert Time for 1000 records: {insert_time:.10f} seconds")

# Measure select time
start_time = time.time()
cursor.execute("SELECT * FROM unencrypted_users")
rows = cursor.fetchall()
select_time = time.time() - start_time
print(f"Select Time for {len(rows)} records: {select_time:.10f} seconds")

# Measure update time
start_time = time.time()
cursor.execute("UPDATE unencrypted_users SET Name = 'James David' WHERE Email LIKE '%@example.com'")
connection.commit()
update_time = time.time() - start_time

# Get number of updated records
updated_records = cursor.rowcount
print(f"Update Time for records with '@example.com' emails: {update_time:.10f} seconds")
print(f"Number of records updated: {updated_records}")

# Close the connection
connection.close()
