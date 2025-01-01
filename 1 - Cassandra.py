from cassandra.cluster import Cluster
from Crypto.Cipher import AES, DES3, Blowfish, ChaCha20, ARC4
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import time

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

# Connect to Cassandra
def connect_to_cassandra():
    cluster = Cluster(['127.0.0.1'])
    session = cluster.connect()
    session.set_keyspace('encryptiondb')  # Use your keyspace name
    return session

# Insert encrypted data into Cassandra
def insert_encrypted_data(session, plain_text, key, algorithm, encryption_time, decryption_time):
    encrypted_text = encrypt_data(plain_text, key, algorithm)
    key_b64 = base64.b64encode(key).decode('utf-8')

    query = """
        INSERT INTO encryption_test_data (
            id, plain_text, encrypted_data, encryption_algorithm, key_size, encryption_time_ms, decryption_time_ms, encryption_key
        ) VALUES (uuid(), %s, %s, %s, %s, %s, %s, %s)
    """
    session.execute(query, (
        plain_text, encrypted_text, algorithm, len(key) * 8, encryption_time, decryption_time, key_b64
    ))
    return encrypted_text

def main():
    session = connect_to_cassandra()

    plain_texts = [
        "1234567890", "9876543210", "HelloWorld", "Encryption", "P@ssw0rd!1", "A1B2C3D4E5",
        "12345678901234567890", "09876543210987654321", "DataEncryptionTest", "SecureDataTesting",
        "P@ssw0rd2023!Secure", "Test123!Encryption", "12345678901234567890123456789012345678901234567890",
        "98765432109876543210987654321098765432109876543210", "ThisIsALongPlaintextForEncryptionTestingPurposes",
        "SecureYourDatabaseWithProperEncryptionMethods", "LongP@ssw0rd123!SecureDataEncryptionTest2023!#",
        "Encryption$Mix123!DataTestForAnalysis2023!AB"
    ]
    algorithms_and_keys = {
        'AES': [16, 24, 32],
        'DES': [24],  # Only triple DES is supported in PyCryptodome
        'Blowfish': [16, 32, 56],
        'ChaCha20': [32],
        'RC4': [5, 16, 32],  # 5 bytes = 40 bits minimum
    }

    for plain_text in plain_texts:
        print(f"\n=== Processing Plain Text: {plain_text} ===")
        for algorithm, key_sizes in algorithms_and_keys.items():
            for key_size in key_sizes:
                key = get_random_bytes(key_size)
                print(f"\n=== Processing {algorithm} with {key_size * 8}-bit key ===")

                # Encrypt and measure encryption time
                e_start_time = time.perf_counter()
                encrypted_text = encrypt_data(plain_text, key, algorithm)
                e_end_time = time.perf_counter()
                encryption_time = (e_end_time - e_start_time) * 1000

                # Decrypt and measure decryption time
                d_start_time = time.perf_counter()
                decrypted_text = decrypt_data(encrypted_text, key, algorithm)
                d_end_time = time.perf_counter()
                decryption_time = (d_end_time - d_start_time) * 1000

                # Log details for each algorithm
                print(f"Encrypted Text ({algorithm}, {key_size * 8} bits): {encrypted_text}")
                print(f"Encryption Time ({algorithm}): {encryption_time:.4f} ms")
                print(f"Decrypted Text ({algorithm}): {decrypted_text}")
                print(f"Decryption Time ({algorithm}): {decryption_time:.4f} ms")

                # Insert data into Cassandra
                insert_encrypted_data(session, plain_text, key, algorithm, encryption_time, decryption_time)
                print(f"Encrypted data inserted for {algorithm} with {key_size * 8}-bit key")

if __name__ == "__main__":
    main()
