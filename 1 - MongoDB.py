from pymongo import MongoClient
from bson.objectid import ObjectId
from Crypto.Cipher import AES, DES3, Blowfish, ChaCha20, ARC4
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import time

# MongoDB connection setup
def connect_to_mongodb():
    try:
        client = MongoClient("mongodb://localhost:27017/")
        db = client['EncryptionDB']
        print("Successfully connected to MongoDB")
        return db
    except Exception as e:
        print(f"Error connecting to MongoDB: {e}")
        return None

# Encryption function
def encrypt_data(plain_text, key, algorithm):
    iv = None
    cipher = None

    if algorithm in ['AES', 'DES', 'Blowfish']:
        iv = get_random_bytes(8 if algorithm in ['DES', 'Blowfish'] else 16)

    if algorithm == 'AES':
        cipher = AES.new(key, AES.MODE_CBC, iv)
    elif algorithm == 'DES':
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
    elif algorithm == 'Blowfish':
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    elif algorithm == 'ChaCha20':
        cipher = ChaCha20.new(key=key)
        iv = cipher.nonce
    elif algorithm == 'RC4':
        cipher = ARC4.new(key)

    if algorithm in ['AES', 'DES', 'Blowfish']:
        padded_text = pad(plain_text.encode(), cipher.block_size)
        encrypted = cipher.encrypt(padded_text)
    else:
        encrypted = cipher.encrypt(plain_text.encode())

    encrypted_text = base64.b64encode((iv + encrypted) if iv else encrypted).decode('utf-8')
    return encrypted_text

# Decryption function
def decrypt_data(encrypted_text, key, algorithm):
    encrypted_data = base64.b64decode(encrypted_text)

    iv = None
    cipher = None

    if algorithm in ['AES', 'DES', 'Blowfish']:
        iv_size = 8 if algorithm in ['DES', 'Blowfish'] else 16
        iv = encrypted_data[:iv_size]
        encrypted_data = encrypted_data[iv_size:]
    elif algorithm == 'ChaCha20':
        iv = encrypted_data[:8]
        encrypted_data = encrypted_data[8:]

    if algorithm == 'AES':
        cipher = AES.new(key, AES.MODE_CBC, iv)
    elif algorithm == 'DES':
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
    elif algorithm == 'Blowfish':
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    elif algorithm == 'ChaCha20':
        cipher = ChaCha20.new(key=key, nonce=iv)
    elif algorithm == 'RC4':
        cipher = ARC4.new(key)

    if algorithm in ['AES', 'DES', 'Blowfish']:
        decrypted_data = unpad(cipher.decrypt(encrypted_data), cipher.block_size)
    else:
        decrypted_data = cipher.decrypt(encrypted_data)

    return decrypted_data.decode('utf-8')

# Generate keys based on desired sizes
def get_algorithm_keys():
    return {
        'AES': [get_random_bytes(16), get_random_bytes(24), get_random_bytes(32)],  # 128, 192, 256 bits
        'DES': [get_random_bytes(24)],  # 192 bits
        'Blowfish': [get_random_bytes(16), get_random_bytes(32), get_random_bytes(56)],  # 128, 256, 448 bits
        'ChaCha20': [get_random_bytes(32)],  # 256 bits
        'RC4': [get_random_bytes(5), get_random_bytes(16), get_random_bytes(32)],  # 40, 128, 256 bits
    }

# Insert encrypted data into MongoDB
def insert_encrypted_data(db, plain_text, key, algorithm, encryption_time, decryption_time):
    encrypted_text = encrypt_data(plain_text, key, algorithm)
    key_b64 = base64.b64encode(key).decode('utf-8')
    record = {
        "plain_text": plain_text,
        "encrypted_data": encrypted_text,
        "encryption_algorithm": algorithm,
        "key_size": len(key) * 8,
        "encryption_time_ms": encryption_time,
        "decryption_time_ms": decryption_time,
        "encryption_key": key_b64
    }
    db.encryption_test_data.insert_one(record)
    print(f"Encrypted data inserted for {algorithm} with key size {len(key) * 8} bits")

# Retrieve and decrypt data from MongoDB
def retrieve_and_decrypt_data(db, record_id):
    record = db.encryption_test_data.find_one({"_id": ObjectId(record_id)})
    if record:
        encrypted_data = record['encrypted_data']
        algorithm = record['encryption_algorithm']
        key = base64.b64decode(record['encryption_key'])
        decrypted_text = decrypt_data(encrypted_data, key, algorithm)
        print(f"Decrypted Text: {decrypted_text}")
    else:
        print("No record found with the given ID")

# Display all records in MongoDB
def display_table_data(db):
    records = list(db.encryption_test_data.find())
    if records:
        print("\n=== Encryption Test Data Table ===")
        for record in records:
            print(record)
    else:
        print("No data available in the collection.")

def main():
    db = connect_to_mongodb()
    if db is None:
        return

    plain_texts = [
        "1234567890", "9876543210", "HelloWorld", "Encryption", "P@ssw0rd!1", "A1B2C3D4E5",
        "12345678901234567890", "09876543210987654321", "DataEncryptionTest", "SecureDataTesting",
        "P@ssw0rd2023!Secure", "Test123!Encryption", "12345678901234567890123456789012345678901234567890",
        "98765432109876543210987654321098765432109876543210", "ThisIsALongPlaintextForEncryptionTestingPurposes",
        "SecureYourDatabaseWithProperEncryptionMethods", "LongP@ssw0rd123!SecureDataEncryptionTest2023!#",
        "Encryption$Mix123!DataTestForAnalysis2023!AB"
    ]

    keys = get_algorithm_keys()

    for plain_text in plain_texts:
        print(f"\n=== Processing Plain Text: {plain_text} ===")
        for algorithm, key_sizes in keys.items():
            for key in key_sizes:
                print(f"\n=== Processing {algorithm} with key size {len(key) * 8} bits ===")
                e_start_time = time.perf_counter()
                encrypted_text = encrypt_data(plain_text, key, algorithm)
                e_end_time = time.perf_counter()
                encryption_time = (e_end_time - e_start_time) * 1000
                print(f"Encrypted Text ({algorithm}): {encrypted_text}")
                print(f"Encryption Time ({algorithm}): {encryption_time} ms")

                d_start_time = time.perf_counter()
                decrypted_text = decrypt_data(encrypted_text, key, algorithm)
                d_end_time = time.perf_counter()
                decryption_time = (d_end_time - d_start_time) * 1000
                print(f"Decrypted Text ({algorithm}): {decrypted_text}")
                print(f"Decryption Time ({algorithm}): {decryption_time} ms")

                insert_encrypted_data(db, plain_text, key, algorithm, encryption_time, decryption_time)

    display_table_data(db)

if __name__ == '__main__':
    main()
