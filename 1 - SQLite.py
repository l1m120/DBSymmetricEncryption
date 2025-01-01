from Crypto.Cipher import AES, DES3, Blowfish, ChaCha20, ARC4
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from tabulate import tabulate
import base64
import time
import sqlite3

# Encryption function
def encrypt_data(plain_text, key, algorithm):
    iv = None
    cipher = None

    if algorithm in ['AES', 'DES3', 'Blowfish']:
        iv = get_random_bytes(8 if algorithm in ['DES3', 'Blowfish'] else 16)

    if algorithm == 'AES':
        cipher = AES.new(key, AES.MODE_CBC, iv)
    elif algorithm == 'DES3':
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
    elif algorithm == 'Blowfish':
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    elif algorithm == 'ChaCha20':
        cipher = ChaCha20.new(key=key)
        iv = cipher.nonce
    elif algorithm == 'RC4':
        cipher = ARC4.new(key)

    if algorithm in ['AES', 'DES3', 'Blowfish']:
        padded_text = pad(plain_text.encode(), cipher.block_size)
        encrypted = cipher.encrypt(padded_text)
    else:
        encrypted = cipher.encrypt(plain_text.encode())

    encrypted_text = base64.b64encode((iv + encrypted) if iv else encrypted).decode('utf-8')
    return encrypted_text

def decrypt_data(encrypted_text, key, algorithm):
    encrypted_data = base64.b64decode(encrypted_text)

    iv = None
    cipher = None

    if algorithm in ['AES', 'DES3', 'Blowfish']:
        iv_size = 8 if algorithm in ['DES3', 'Blowfish'] else 16
        iv = encrypted_data[:iv_size]
        encrypted_data = encrypted_data[iv_size:]
    elif algorithm == 'ChaCha20':
        iv = encrypted_data[:8]
        encrypted_data = encrypted_data[8:]

    if algorithm == 'AES':
        cipher = AES.new(key, AES.MODE_CBC, iv)
    elif algorithm == 'DES3':
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
    elif algorithm == 'Blowfish':
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    elif algorithm == 'ChaCha20':
        cipher = ChaCha20.new(key=key, nonce=iv)
    elif algorithm == 'RC4':
        cipher = ARC4.new(key)

    if algorithm in ['AES', 'DES3', 'Blowfish']:
        decrypted_data = unpad(cipher.decrypt(encrypted_data), cipher.block_size)
    else:
        decrypted_data = cipher.decrypt(encrypted_data)

    return decrypted_data.decode('utf-8')

def get_algorithm_keys():
    return {
        # AES: Supports 128, 192, and 256 bits
        'AES_128': get_random_bytes(16),  # 16 bytes = 128 bits
        'AES_192': get_random_bytes(24),  # 24 bytes = 192 bits
        'AES_256': get_random_bytes(32),  # 32 bytes = 256 bits

        # DES3 (Triple DES) for 192-bit keys
        'DES3_192': get_random_bytes(24),  # 24 bytes = 192 bits (for 3DES)

        # Blowfish: Supports 128, 256, and 448 bits
        'Blowfish_128': get_random_bytes(16),  # 16 bytes = 128 bits
        'Blowfish_256': get_random_bytes(32),  # 32 bytes = 256 bits
        'Blowfish_448': get_random_bytes(56),  # 56 bytes = 448 bits

        # ChaCha20: Supports only 256 bits
        'ChaCha20_256': get_random_bytes(32),  # 32 bytes = 256 bits

        # RC4: Supports 40 to 256 bits
        'RC4_40': get_random_bytes(5),  # 5 bytes = 40 bits
        'RC4_128': get_random_bytes(16),  # 16 bytes = 128 bits
        'RC4_256': get_random_bytes(32),  # 32 bytes = 256 bits
    }

def connect_to_db():
    try:
        conn = sqlite3.connect("EncryptionDB.sqlite")
        cursor = conn.cursor()

        # Create table if not exists
        cursor.execute(''' 
            CREATE TABLE IF NOT EXISTS encryption_test_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                plain_text TEXT,
                encrypted_data TEXT,
                encryption_algorithm TEXT,
                key_size INTEGER,
                encryption_time_ms REAL,
                decryption_time_ms REAL,
                encryption_key TEXT
            )
        ''')
        conn.commit()
        return conn
    except sqlite3.Error as err:
        print(f"Error: {err}")
        return None

def insert_encrypted_data(conn, plain_text, key, algorithm, encryption_time, decryption_time):
    encrypted_text = encrypt_data(plain_text, key, algorithm)
    key_b64 = base64.b64encode(key).decode('utf-8')

    # Manually set DES3 key size to 192 bits
    if algorithm == 'DES3':
        key_size = 192  # DES3 with 192-bit key size
    else:
        key_size = len(key) * 8

    cursor = conn.cursor()
    cursor.execute(''' 
        INSERT INTO encryption_test_data (plain_text, encrypted_data, encryption_algorithm, key_size, encryption_time_ms, decryption_time_ms, encryption_key)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (plain_text, encrypted_text, algorithm, key_size, encryption_time, decryption_time, key_b64))
    conn.commit()
    print(f"Encrypted data inserted for {algorithm}")

def display_table_data(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM encryption_test_data")
    rows = cursor.fetchall()
    columns = [desc[0] for desc in cursor.description]

    if rows:
        print("\n=== Encryption Test Data Table ===")
        print(tabulate(rows, headers=columns, tablefmt="grid"))
    else:
        print("No data available in the table.")

def main():
    conn = connect_to_db()

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
        for algorithm_key, key in keys.items():
            algorithm, key_size = algorithm_key.split('_')
            print(f"\n=== Processing {algorithm} ({key_size} bits) ===")

            e_start_time = time.perf_counter()
            encrypted_text = encrypt_data(plain_text, key, algorithm)
            e_end_time = time.perf_counter()
            encryption_time = (e_end_time - e_start_time) * 1000

            d_start_time = time.perf_counter()
            decrypted_text = decrypt_data(encrypted_text, key, algorithm)
            d_end_time = time.perf_counter()
            decryption_time = (d_end_time - d_start_time) * 1000

            insert_encrypted_data(conn, plain_text, key, algorithm, encryption_time, decryption_time)

    display_table_data(conn)
    conn.close()

if __name__ == '__main__':
    main()
