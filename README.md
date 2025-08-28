# 🔐 Database Encryption: Symmetric Encryption Algorithms

A **Python-based project** demonstrating how **symmetric encryption algorithms** can be applied in **database security**.  
This project evaluates multiple algorithms and simulates **real-world scenarios** such as protecting sensitive user data at the **field-level**.  

---

## 🚀 Project Overview
The project is structured into **two phases**:

### 1️⃣ Phase 1: Symmetric Encryption Algorithm Evaluation
- Benchmarked the performance of **AES, DES, Blowfish, RC4, and ChaCha20**  
- Measured **encryption/decryption speed**, **key size impact**, and **storage overhead**  
- Tested with different plaintext types: numeric, alphabetic, and alphanumeric (short, medium, long)  

### 2️⃣ Phase 2: Real-world Field-Level Encryption
- Simulated **user database encryption** to protect sensitive fields (`email`, `creditcard`)  
- Compared performance across **MySQL, SQLite, MongoDB, and Apache Cassandra**  
- Inserted and encrypted **1000 random user records** to mimic realistic applications  

---

## ✨ Key Features
- 🔑 **Encryption Algorithms Implemented:**  
  - AES (128, 192, 256 bits)  
  - DES (192 bits)  
  - Blowfish (128–448 bits)  
  - RC4 (40–256 bits)  
  - ChaCha20 (256 bits)  

- 📊 **Performance Testing:**  
  - Tracks encryption time, decryption time, key size, and algorithm efficiency  

- 🗄 **Database Integration:**  
  - Supports **MySQL, SQLite, MongoDB, Apache Cassandra**  

- 🛡 **Field-level Protection:**  
  - Encrypts sensitive fields like **emails & credit cards**  

---

## 🛠️ Technologies & Tools
- **Python 3.x**  
- **Databases:** MySQL, SQLite, MongoDB, Cassandra  
- **Crypto Libraries:** PyCryptodome, Cryptography  

---

## 📊 Example Output
| Algorithm  | Key Size | Encryption Time (ms) | Decryption Time (ms) |
|------------|----------|-----------------------|-----------------------|
| AES        | 256      | 5.4                   | 4.8                   |
| Blowfish   | 448      | 6.1                   | 5.5                   |
| ChaCha20   | 256      | 4.2                   | 4.0                   |

*(Values for demonstration — replace with your actual benchmark results)*  

---

## 📖 Learning Outcomes
- Gained hands-on experience with **database security & encryption**  
- Understood trade-offs between **performance, key size, and security strength**  
- Applied encryption in **practical database scenarios** (field-level protection)  
- Worked with both **SQL and NoSQL databases**  

---

## 👨‍💻 Author
Developed by **Zi Xuan Lim**  
📍 Sunway University | BSc (Hons) Computer Science  

---

## 📝 License
This project is for **educational purposes only**.
