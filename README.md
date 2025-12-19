# 🔐 SecureChain – Blockchain-Based Encrypted Messaging System

SecureChain is a **web-based encrypted messaging application** built as part of a **Project-Based Learning (PBL)** initiative.
The project demonstrates the **practical implementation of cryptography and blockchain concepts** using Python.

Messages are encrypted using **AES + RSA hybrid encryption** and stored immutably in a **custom blockchain implemented from scratch**.

---

## 📌 Features

- Secure user authentication with hashed passwords
- End-to-end encrypted messaging
- Custom blockchain for immutable message storage
- Blockchain explorer to visualize encrypted blocks
- Node status page for multi-device access
- Lightweight SQLite database integration

---

## 🛠️ Technology Stack

### Backend
- Python
- Flask
- Custom Blockchain (Python)

### Cryptography
- AES (message encryption)
- RSA (AES key encryption)
- bcrypt (password hashing)

### Frontend
- HTML
- CSS

### Database
- SQLite3

---

## 📦 Libraries & Versions

```
Flask==3.1.2
bcrypt==5.0.0
pycryptodome==3.23.0
```

---

## 🔄 System Workflow

1. User registers and logs in securely.
2. Message is encrypted using AES.
3. AES key is encrypted using receiver’s RSA public key.
4. Encrypted message and key are stored as a new block in the blockchain.
5. Receiver decrypts AES key using RSA private key.
6. Message is decrypted and displayed in the chat interface.
7. Any tampering breaks the blockchain hash integrity.

---

## 🧪 Core Components

### Blockchain
- Genesis block initialization
- Hash chaining between blocks
- Immutable storage of encrypted messages

### Security
- Password hashing using bcrypt
- Hybrid encryption (AES + RSA)

### Database
- SQLite used for user credentials and message indexing

---

## 🖥️ Screenshots

This repository includes screenshots of:
- Login & authentication system
- Encrypted chat interface
- Blockchain explorer
- Node status & network access
- Backend blockchain data structure

---

## 🚀 How to Run the Project

1. Clone the repository:
```bash
git clone <repository-url>
cd SecureChain
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python app.py
```

4. Open in browser:
```
http://localhost:5001
```

---

## 📚 Learning Outcomes

- Hands-on implementation of AES & RSA
- Understanding blockchain internals
- Secure backend development using Python
- Applying cryptography to real-world scenarios

---

## ⚠️ Disclaimer

This project is developed **for educational purposes only** and is not intended for production deployment.

---

## 👨‍💻 Author

**Naitik Dhiman**  
B.Tech CSE (Cybersecurity)  
Project-Based Learning (PBL)
