from pymongo import MongoClient
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

# Measure operation time
def measure_time(func, *args):
    start_time = time.perf_counter()
    func(*args)
    end_time = time.perf_counter()
    return end_time - start_time

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["EncryptionDB"]
collection = db["unencrypted_users"]

# Drop collection if exists (for clean insertion)
collection.drop()

# Generate and insert 1000 sample records
sample_data = [
    {"Name": generate_name(), "Email": generate_email(generate_name()), "CreditCard": generate_credit_card()}
    for _ in range(1000)
]

# Measure insert time
insert_time = measure_time(lambda: collection.insert_many(sample_data))

print(f"Insert Time {insert_time:.10f} seconds")

# Measure select time (fetch all records)
select_time = measure_time(lambda: collection.find().limit(1000))

print(f"Select Time (fetch 1000 records): {select_time:.10f} seconds")

# Measure update time (update records matching a condition)
update_time = 0
updated_count = 0
emails_to_update = collection.find({"Email": {"$regex": "@example.com$"}})

# Update each record with a new name
for user in emails_to_update:
    update_time += measure_time(lambda: collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"Name": "James David"}}
    ))
    updated_count += 1

print(f"Update Time (records with email ending in '@example.com'): {update_time:.10f} seconds.")
print(f"Number of records updated: {updated_count}")

# Close the connection
client.close()
