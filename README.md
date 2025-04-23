# Python Asymmetric Encryption Tool

A Python-based command-line tool for performing asymmetric encryption and digital signing using **RSA**, **Ed25519**, and **X25519** algorithms.

---

## Introduction

This tool supports secure operations including:
- Key generation
- File encryption and decryption
- Digital signing and verification

All features are accessible via a simple command-line interface (CLI), making it ideal for developers and cybersecurity professionals.

---

## Architecture

### Paradigm

The tool uses **Object-Oriented Programming (OOP)** to structure the logic into modular and maintainable components.

### KeyManager Class

Main class handling all cryptographic operations:

**Attributes:**
- `algorithm` – (str): RSA, Ed25519, or X25519
- `generate_keypair` – (bool): Auto-generates keys on init if `True`

**Constructor:**
```python
def __init__(self, algorithm, generate_keypair=False)

Initializes the class with selected algorithm and optionally generates keys.
 KeyManager Methods

    encrypt_file_with_public_key_RSA(...)

    decrypt_file_with_private_key_RSA(...)

    encrypt_file(...) – X25519 + AES

    decrypt_file(...)

    sign_file_RSA(...) / verify_signature_RSA(...)

    sign_file_ed25519(...) / verify_signature_ed25519(...)

    simulate_sign_with_public_key_ed25519(...) / simulate_verify_with_public_key_ed25519(...)

    _generate_rsa_key()

    _generate_ed25519_key()

    generate_x25519_keys()

    generate_x25519_keys_and_save(...)

    load_private_key(...) / load_public_key(...)

    load_ed25519_private_key(...) / load_ed25519_public_key(...)

    load_x25519_private_key(...) / load_x25519_public_key(...)
```
 Command Line Interface (CLI)

A class-based CLI is implemented using argparse, supporting:
- Encryption & decryption
- Key generation
- Signing & verification

 External Libraries
The only external dependency is:
```
pip install cryptography
```
 Usage Examples
 RSA
```
# Generate RSA Key Pair
python Encryption.py --algorithm RSA --keypair

# Encrypt File
python Encryption.py --algorithm RSA --encrypt-file-RSA input.txt --load-public-key public_key_RSA.pem --output-file output_rsa.enc

# Decrypt File
python Encryption.py --algorithm RSA --decrypt-file-RSA output_rsa.enc --load-private-key private_key_RSA.pem --output-file decrypted.txt

# Sign File
python Encryption.py --sign_file_RSA private_key_RSA.pem input.txt signature.sig

# Verify Signature
python Encryption.py --verify --public_key public_key_RSA.pem --file input.txt --signature signature.sig

```
Ed25519
```
# Generate Keys
python Encryption.py --algorithm Ed25519 --keypair

# Sign File
python Encryption.py --sign_file_ed25519 private_key_Ed.pem input.txt signature_ed.sig

# Verify Signature
python Encryption.py --verify_ed25519 public_key_Ed.pem input.txt signature_ed.sig

# Simulate Sign & Verify (Not Secure)
python Encryption.py --simulate_sign_ed25519 public_key_Ed.pem input.txt fake.sig
python Encryption.py --simulate_verify_ed25519 public_key_Ed.pem input.txt fake.sig

```
Encrypt & Decrypt Image (X25519)
```
# Generate X25519 Keys
python Encryption.py --generate_x25519_keys private_x25519.pem public_x25519.pem

# Encrypt Image
python Encryption.py --encrypt_file_X25519 private_x25519.pem public_x25519.pem image.jpg

# Decrypt Image
python Encryption.py --decrypt_file_X25519 private_x25519.pem public_x25519.pem image.jpg.enc

```
PEM Key Format
Ed25519
- private_key_Ed25519.pem: Used for signing
- public_key_Ed25519.pem: Used for verifying signatures

RSA
- private_key_RSA.pem: Used for decryption & signing
- public_key_RSA.pem: Used for encryption & verifying signatures
Signature Examples
RSA Signature
```
python Encryption.py --sign_file_RSA private_key_RSA.pem report.pdf report_signature.sig
```
Ed25519 Signature
```
python Encryption.py --sign_file_ed25519 private_key_Ed.pem report.pdf report_signature.sig
```
Conclusion
This tool provides robust cryptographic functionality using modern best practices:
    RSA for encryption and signing
    Ed25519 for lightweight digital signatures
    X25519 for secure key exchange
With its CLI interface and clear modular structure, it’s a flexible tool for developers working on secure communications, data protection, or educational cryptography projects.
