# 🔐 Database Encryption: Symmetric Encryption Algorithms  

A **Python-based project** demonstrating how **symmetric encryption algorithms** can be applied in **database security**.  
The project evaluates multiple algorithms and simulates **real-world scenarios** such as protecting sensitive user data at the **field-level**.  

---

## 🚀 Project Overview
The project is structured into **two phases**:

### 1️⃣ Phase 1: Symmetric Encryption Algorithm Evaluation  
- Benchmarked **AES, DES, Blowfish, RC4, ChaCha20** across multiple key sizes  
- Measured **encryption/decryption speed** and **storage overhead**  
- Tested on various plaintext types: numeric, alphabetic, alphanumeric (short, medium, long)  

### 2️⃣ Phase 2: Real-world Field-Level Encryption  
- Simulated **user database encryption** for sensitive fields (`email`, `creditcard`)  
- Compared results across **MySQL, SQLite, MongoDB, and Apache Cassandra**  
- Inserted and encrypted **1000 random user records** per database  

---

## 📜 Script Description

### ⚡ Phase 1: Encryption Test Data Generation  
- **File Names:** Python files labeled starting with `1`  
- **Purpose:** Inserts data into the `encryption_test_data` table with attributes:  

| **Attribute**          | **Description**                       |
|------------------------|---------------------------------------|
| `id`                   | Unique identifier                     |
| `plain_text`           | Input data to be encrypted            |
| `encrypted_data`       | Resulting encrypted output             |
| `encryption_algorithm` | Encryption algorithm used             |
| `key_size`             | Size of the encryption key            |
| `encryption_time`      | Time taken for encryption             |
| `decryption_time`      | Time taken for decryption             |
| `encryption_key`       | Key used for encryption               |

- **Algorithms Tested:**  

| **Algorithm** | **Key Sizes**        |
|---------------|----------------------|
| AES           | 128, 192, 256 bits   |
| DES           | 192 bits             |
| Blowfish      | 128, 256, 448 bits   |
| RC4           | 40, 128, 256 bits    |
| ChaCha20      | 256 bits             |

- **Plaintext Variations:**  

|                | **Numeric**                                         | **Alphabetic**                                      | **Alphanumeric**                                                   |
|----------------|-----------------------------------------------------|----------------------------------------------------|--------------------------------------------------------------------|
| **Short**      | 1234567890, 9876543210                             | HelloWorld, Encryption                             | P@ssw0rd!1, A1B2C3D4E5                                             |
| **Medium**     | 12345678901234567890, 09876543210987654321         | DataEncryptionTest, SecureDataTesting              | P@ssw0rd2023!Secure, Test123!Encryption                            |
| **Long**       | 12345678901234567890123456789012345678901234567890 <br> 98765432109876543210987654321098765432109876543210 | ThisIsALongPlaintextForEncryptionTestingPurposes <br> SecureYourDatabaseWithProperEncryptionMethods | LongP@ssw0rd123!SecureDataEncryptionTest2023!# <br> Encryption$Mix123!DataTestForAnalysis2023!AB |

- **Supported Databases:**  
  - MySQL  
  - SQLite  
  - MongoDB  
  - Apache Cassandra  

---

### ⚡ Phase 2: Real-world Scenario Simulation  
- **File Names:** Python files labeled starting with `2` and `3`  

#### Files Starting with `2`  
- Inserts **1000 unencrypted random user records** into the `unencrypted_users` table  
- Attributes:  

| **Attribute** | **Description**       |
|---------------|-----------------------|
| `id`          | Unique identifier     |
| `name`        | User’s name           |
| `email`       | User’s email address  |
| `creditcard`  | User’s credit card    |

#### Files Starting with `3`  
- Inserts **1000 user records with field-level encryption** (`email`, `creditcard`)  
- Stored in `users` table with encrypted fields using multiple algorithms  
- Attributes:  

| **Attribute** | **Description**        |
|---------------|------------------------|
| `id`          | Unique identifier      |
| `name`        | User’s name            |
| `email`       | Encrypted email        |
| `creditcard`  | Encrypted credit card  |

- **Encryption Key Sizes Used:**  

| **Algorithm** | **Key Sizes** |
|---------------|---------------|
| AES           | 256 bits      |
| DES           | 192 bits      |
| Blowfish      | 448 bits      |
| RC4           | 256 bits      |
| ChaCha20      | 256 bits      |

---

## 🛠️ Technologies & Tools
- **Python 3.x**  
- **Databases:** MySQL, SQLite, MongoDB, Cassandra  
- **Crypto Libraries:** PyCryptodome, Cryptography  

---

## 📖 Learning Outcomes
- Implemented and benchmarked **symmetric encryption algorithms**  
- Learned trade-offs between **security strength vs performance**  
- Simulated **real-world field-level encryption in databases**  
- Applied concepts across **SQL & NoSQL systems**  

---

## 👨‍💻 Author
Developed by **Zi Xuan Lim**  
📍 Sunway University | BSc (Hons) in Computer Science  

---

## 📝 License
This project is for **educational purposes only**.  

