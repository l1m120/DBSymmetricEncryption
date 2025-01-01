from Crypto.Cipher import AES, DES3, Blowfish, ChaCha20, ARC4
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import time
import mysql.connector

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

# Reconnect if connection is closed
def reconnect_if_needed(conn):
    if not conn.is_connected():
        print("Reconnecting to the database...")
        conn = connect_to_db()
    return conn

# Define keys for each algorithm
def get_algorithm_keys():
    return {
        'AES': [get_random_bytes(size // 8) for size in [128, 192, 256]],
        'DES': [get_random_bytes(24)],
        'Blowfish': [get_random_bytes(size // 8) for size in [128, 256, 448]],
        'ChaCha20': [get_random_bytes(32)],
        'RC4': [get_random_bytes(size // 8) for size in [40, 128, 256]],
    }

# Define list of plain text values
plain_texts = [
    "1234567890", "9876543210", "HelloWorld", "Encryption", "P@ssw0rd!1", "A1B2C3D4E5",
    "12345678901234567890", "09876543210987654321", "DataEncryptionTest", "SecureDataTesting",
    "P@ssw0rd2023!Secure", "Test123!Encryption", "12345678901234567890123456789012345678901234567890",
    "98765432109876543210987654321098765432109876543210", "ThisIsALongPlaintextForEncryptionTestingPurposes",
    "SecureYourDatabaseWithProperEncryptionMethods", "LongP@ssw0rd123!SecureDataEncryptionTest2023!#",
    "Encryption$Mix123!DataTestForAnalysis2023!AB"
]

# Connect to the database
def connect_to_db():
    print("Connecting to the database...")
    try:
        conn = mysql.connector.connect(
            host='localhost',
            user='root',
            password='W7301@jqir#',
            database='EncryptionDB'
        )
        conn.autocommit = True
        return conn
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return None

# Insert encrypted data into the database
def insert_encrypted_data(conn, cursor, plain_text, key, algorithm, encryption_time, decryption_time):
    try:
        encrypted_text = encrypt_data(plain_text, key, algorithm)
        key_b64 = base64.b64encode(key).decode('utf-8')
        cursor.execute('''
            INSERT INTO encryption_test_data 
            (plain_text, encrypted_data, encryption_algorithm, key_size, encryption_time_ms, decryption_time_ms, encryption_key) 
            VALUES (%s, %s, %s, %s, %s, %s, %s)''',
            (plain_text, encrypted_text, algorithm, len(key) * 8, encryption_time, decryption_time, key_b64)
        )
        conn.commit()
        print(f"Encrypted data inserted for {algorithm}")
    except mysql.connector.Error as e:
        print(f"Error inserting data for {algorithm}: {e}")
        conn.rollback()

def main():
    conn = connect_to_db()
    cursor = conn.cursor()

    # Get keys for all algorithms
    keys = get_algorithm_keys()

    # Loop through algorithms and key sizes, then loop through all plain text values
    for plain_text in plain_texts:
        for algorithm, key_list in keys.items():
            for key in key_list:
                print(f"\n=== Processing {plain_text} with {algorithm} and key size {len(key) * 8} bits ===")

                # Encryption
                e_start_time = time.perf_counter()
                encrypted_text = encrypt_data(plain_text, key, algorithm)
                e_end_time = time.perf_counter()
                encryption_time = (e_end_time - e_start_time) * 1000  # Convert to milliseconds
                print(f"Encrypted Text ({algorithm}, {len(key) * 8} bits): {encrypted_text}")
                print(f"Encryption Time ({algorithm}, {len(key) * 8} bits): {encryption_time} ms")

                # Decryption
                d_start_time = time.perf_counter()
                decrypted_text = decrypt_data(encrypted_text, key, algorithm)
                d_end_time = time.perf_counter()
                decryption_time = (d_end_time - d_start_time) * 1000  # Convert to milliseconds
                print(f"Decrypted Text ({algorithm}, {len(key) * 8} bits): {decrypted_text}")
                print(f"Decryption Time ({algorithm}, {len(key) * 8} bits): {decryption_time} ms")

                # To ensure the connection is open before saving to the database
                conn = reconnect_if_needed(conn)

                # Insert encrypted data into the database
                insert_encrypted_data(conn, cursor, plain_text, key, algorithm, encryption_time, decryption_time)

    cursor.close()
    conn.close()

if __name__ == '__main__':
    main()
