import argparse
import hashlib
import base64

import args
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import padding as sym_padding  # For block padding

class KeyManager:
    def __init__(self, algorithm, generate_keypair=False):
        self.algorithm = algorithm
        self.generate_keypair = generate_keypair

    def encrypt_file_with_private_key_RSA(self, private_key, input_file, output_file):
        """Encrypt a file using an RSA private key (NOT secure or standard)."""
        with open(input_file, "rb") as f:
            data = f.read()

        ciphertext = private_key.sign(
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        with open(output_file, "wb") as f:
            f.write(ciphertext)

        print(f"[RSA PRIVATE ENCRYPTION] File encrypted with private key and saved to {output_file}.")

    def decrypt_file_with_public_key_RSA(self, public_key, encrypted_file, output_file):
        """Decrypt a file using an RSA public key (NOT secure or standard)."""
        with open(encrypted_file, "rb") as f:
            ciphertext = f.read()

        try:
            # Try to recover original data via signature verification (works only with original data)
            # Since there's no decryption method, this only makes sense if we're "verifying"
            print("[RSA PUBLIC DECRYPTION] This is a simulated decryption based on verifying a signature.")
            with open(output_file, "wb") as f:
                f.write(b"[Simulated decryption not supported natively by RSA public keys]")
            print(f"Output written to {output_file}.")
        except Exception as e:
            print(f"[ERROR] Decryption failed: {e}")

    # 14.

    def simulate_sign_with_public_key_ed25519(self, public_key_path, file_path, simulated_signature_path):
        """Simulates signing a file using the Ed25519 public key (NOT cryptographically valid)."""
        with open(public_key_path, "rb") as pub_file:
            public_key_bytes = pub_file.read()

        with open(file_path, "rb") as f:
            file_data = f.read()

        # Simulated: hash(public_key + file_data)
        combined = public_key_bytes + file_data
        digest = hashlib.sha256(combined).digest()

        with open(simulated_signature_path, "wb") as sig_file:
            sig_file.write(digest)

        print(f"[SIMULATED] Signature created using public key and saved to: {simulated_signature_path}")

    def simulate_verify_with_public_key_ed25519(self, public_key_path, file_path, simulated_signature_path):
        """Simulates verifying a fake Ed25519 signature created using public key."""
        with open(public_key_path, "rb") as pub_file:
            public_key_bytes = pub_file.read()

        with open(file_path, "rb") as f:
            file_data = f.read()

        with open(simulated_signature_path, "rb") as sig_file:
            expected_digest = sig_file.read()

        actual_digest = hashlib.sha256(public_key_bytes + file_data).digest()

        if actual_digest == expected_digest:
            print("[SIMULATED] Signature is valid.")
        else:
            print("[SIMULATED] Invalid signature.")
    # 13. Signing files (both text and binary) using the private key. This functionality must include verifying the generated signatures using the corresponding public key. For RSA
    def sign_file_RSA(self, private_key_path, file_path, signature_output_path):
        """Signs a file using the RSA private key and saves the signature."""
        private_key = self.load_private_key(private_key_path)

        with open(file_path, "rb") as file:
            file_data = file.read()

        signature = private_key.sign(
            file_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        with open(signature_output_path, "wb") as sig_file:
            sig_file.write(signature)

        print(f"[RSA] File signed. Signature saved to: {signature_output_path}")

    def verify_signature_RSA(self, public_key_path, file_path, signature_path):
        """Verifies the signature of a file using the RSA public key."""
        public_key = self.load_public_key(public_key_path)

        with open(file_path, "rb") as file:
            file_data = file.read()

        with open(signature_path, "rb") as sig_file:
            signature = sig_file.read()

        print(f"[DEBUG] Verifying RSA Signature:")
        print(f"[DEBUG] File: {file_path} | Signature: {signature_path} | Public Key: {public_key_path}")

        try:
            public_key.verify(
                signature,
                file_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("[RSA] Signature is valid.")
        except InvalidSignature:
            print("[RSA] Invalid signature.")



    # 11. Signing Files using the public key Ed25519
    # Sign file using Ed25519 private key
    def sign_file_ed25519(self, private_key_path, file_path, signature_output_path):
        """Signs a file using the Ed25519 private key and saves the signature."""
        private_key = self.load_ed25519_private_key(private_key_path)

        with open(file_path, "rb") as file:
            file_data = file.read()

        signature = private_key.sign(file_data)

        with open(signature_output_path, "wb") as signature_file:
            signature_file.write(signature)

        print(f"File signed and signature saved to: {signature_output_path}")

    # Verify file signature using Ed25519 public key
    def verify_signature_ed25519(self, public_key_path, file_path, signature_path):
        """Verifies the signature of a file using the Ed25519 public key."""
        public_key = self.load_ed25519_public_key(public_key_path)

        with open(file_path, "rb") as file:
            file_data = file.read()

        with open(signature_path, "rb") as signature_file:
            signature = signature_file.read()

        print(f"[DEBUG] Verifying file: {file_path}")
        print(f"[DEBUG] Signature length: {len(signature)}")
        print(f"[DEBUG] File data length: {len(file_data)}")

        try:
            public_key.verify(signature, file_data)
            print("Signature is valid.")
        except InvalidSignature:
            print("Invalid signature.")

    # 11 Signing files (both text and binary) using the public key. This functionality must include verifying the generated signatures using the corresponding private key. for RSA


    def sign_file_RSA(self, private_key_path, file_path, signature_output_path):
        """Signs a file using the private RSA key and saves the signature."""
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None)

        # Read file content
        with open(file_path, "rb") as file:
            file_data = file.read()

        # Sign the file data using RSA private key
        signature = private_key.sign(
            file_data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        # Save signature to a file
        with open(signature_output_path, "wb") as signature_file:
            signature_file.write(signature)

        print(f"File signed and signature saved to: {signature_output_path}")
    def verify_signature_RSA(self, public_key_path, file_path, signature_path):
        """Verifies the signature of a file using the RSA public key."""
        with open(public_key_path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(key_file.read())

        # Read the file data and signature
        with open(file_path, "rb") as file:
            file_data = file.read()

        with open(signature_path, "rb") as signature_file:
            signature = signature_file.read()

        try:
            # Verify the signature using RSA public key
            public_key.verify(
                signature,
                file_data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            print("Signature is valid.")
        except InvalidSignature:
            print("Invalid signature.")
#


# 10 Generate X25519 keys
    def generate_x25519_keys_and_save(self, private_key_path, public_key_path):
        """Generate an X25519 key pair and save them to files."""
        private_key, public_key = self.generate_x25519_keys()

        # Save private key
        with open(private_key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Save public key
        with open(public_key_path, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ))

        print(f"X25519 keys generated and saved: \nPrivate Key: {private_key_path} \nPublic Key: {public_key_path}")

    def load_x25519_private_key(self, private_key_path):
        """Load an X25519 private key from a file."""
        with open(private_key_path, "rb") as f:
            return x25519.X25519PrivateKey.from_private_bytes(f.read())

    def load_x25519_public_key(self, public_key_path):
        """Load an X25519 public key from a file."""
        with open(public_key_path, "rb") as f:
            return x25519.X25519PublicKey.from_public_bytes(f.read())
#10.START : Encrypting files (both text and binary) using the private key. This functionality must include decrypting the same files using the corresponding public key. for Ed25519
    def generate_x25519_keys(self):
        # Generate X25519 key exchange keys
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key


    def encrypt_file(self, sender_exchange_private_key, recipient_exchange_public_key, input_file, output_file):
        # Generate shared key using X25519
        shared_key = sender_exchange_private_key.exchange(recipient_exchange_public_key)

        # Derive encryption key from shared key using HKDF
        encryption_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'file-encryption'
        ).derive(shared_key)

        # Encrypt file
        with open(input_file, "rb") as f:
            plaintext = f.read()

        iv = os.urandom(16)  # Generate random IV
        cipher = Cipher(algorithms.AES(encryption_key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        with open(output_file, "wb") as f:
            f.write(iv + ciphertext)

        print(f"File encrypted and saved to {output_file}")

    def decrypt_file(self, recipient_exchange_private_key, sender_exchange_public_key, encrypted_file, output_file):
        # Generate shared key using X25519
        shared_key = recipient_exchange_private_key.exchange(sender_exchange_public_key)

        # Derive encryption key from shared key using HKDF
        encryption_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'file-encryption'
        ).derive(shared_key)

        # Decrypt file
        with open(encrypted_file, "rb") as f:
            ciphertext = f.read()

        iv = ciphertext[:16]  # Extract IV
        ciphertext = ciphertext[16:]  # Extract actual ciphertext

        cipher = Cipher(algorithms.AES(encryption_key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        with open(output_file, "wb") as f:
            f.write(plaintext)

        print(f"File decrypted and saved to {output_file}")
#10.Finish Encrypting files (both text and binary) using the private key. This functionality must include decrypting the same files using the corresponding public key. for Ed25519
    def generate_key(self):
        if self.algorithm == "RSA":
            return self._generate_rsa_key()
        elif self.algorithm == "Ed25519":
            return self._generate_ed25519_key()
        else:
            raise ValueError("Unsupported algorithm. Only RSA and Ed25519 are supported.")
#1
    def _generate_rsa_key(self):  # Generation of public and private keys for RSA
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Save private key to a file
        with open("private_key_RSA.pem", "wb") as private_file:
            private_file.write(private_pem)

        # Save public key to a file
        with open("public_key_RSA.pem", "wb") as public_file:
            public_file.write(public_pem)

        if self.generate_keypair:
            return "Private and public RSA keys generated and saved to 'private_key_RSA.pem' and 'public_key_RSA.pem'."
        else:
            return "RSA key generated."

    def encrypt_file_with_public_key_RSA(self, public_key, input_file, output_file):
        with open(input_file, "rb") as f:
            data = f.read()

        # Encrypt data with the public key
        ciphertext = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        with open(output_file, "wb") as f:
            f.write(ciphertext)

        print(f"File encrypted and saved as {output_file}.")

    def decrypt_file_with_private_key_RSA(self, private_key, encrypted_file, output_file):
        with open(encrypted_file, "rb") as f:
            ciphertext = f.read()

        # Decrypt data with the private key
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        with open(output_file, "wb") as f:
            f.write(plaintext)

        print(f"File decrypted and saved as {output_file}.")


    def _generate_ed25519_key(self):  # Generation of public and private keys for Ed25519
        # Generate private and public keys
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        # Convert keys to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Save private key to a file
        with open("private_key_Ed.pem", "wb") as private_file:
            private_file.write(private_pem)

        # Save public key to a file
        with open("public_key_Ed.pem", "wb") as public_file:
            public_file.write(public_pem)

        if self.generate_keypair:
            return "Private and public Ed25519 keys generated and saved to 'private_key_Ed.pem' and 'public_key_Ed.pem'."
        else:
            return "Ed25519 key generated."

    # Load private and public keys from .pem files for RSA
    def load_private_key(self, filename):
        with open(filename, "rb") as private_file:
            private_key = serialization.load_pem_private_key(
                private_file.read(),
                password=None
            )
        return private_key

    def load_public_key(self, filename):
        with open(filename, "rb") as public_file:
            public_key = serialization.load_pem_public_key(
                public_file.read()
            )
        return public_key

    # Load Ed25519 private key from a .pem file
    def load_ed25519_private_key(self, filename):
        with open(filename, "rb") as private_file:
            private_key = serialization.load_pem_private_key(
                private_file.read(),
                password=None
            )
        if not isinstance(private_key, Ed25519PrivateKey):
            raise ValueError("The loaded private key is not an Ed25519 key.")
        return private_key

    # Load Ed25519 public key from a .pem file
    def load_ed25519_public_key(self, filename):
        with open(filename, "rb") as public_file:
            public_key = serialization.load_pem_public_key(
                public_file.read()
            )
        if not isinstance(public_key, Ed25519PublicKey):
            raise ValueError("The loaded public key is not an Ed25519 key.")
        return public_key



class CommandLineInterface:
    def __init__(self):

        self.parser = argparse.ArgumentParser(description="RSA & Ed25519 File Operations")
        self.parser.add_argument(
            "--algorithm",
            choices=["RSA", "Ed25519", "X25519"],
            help="Specify the algorithm for key generation (RSA or Ed25519)"
        )

        self.parser.add_argument('--encrypt_with_private_RSA', nargs=3,
                                 metavar=('PRIVATE_KEY_PATH', 'INPUT_FILE', 'OUTPUT_FILE'),
                                 help="Encrypt file using RSA private key (not standard)")

        self.parser.add_argument('--decrypt_with_public_RSA', nargs=3,
                                 metavar=('PUBLIC_KEY_PATH', 'ENCRYPTED_FILE', 'OUTPUT_FILE'),
                                 help="Decrypt file using RSA public key (not standard)")

        self.parser.add_argument("--encrypt_file_X25519", nargs=3, metavar=("PRIVATE_KEY", "PUBLIC_KEY", "INPUT_FILE"),
                            help="Encrypt a file using X25519. Requires private key, public key, and input file.")
        self.parser.add_argument("--decrypt_file_X25519", nargs=3, metavar=("PRIVATE_KEY", "PUBLIC_KEY", "ENCRYPTED_FILE"),
                            help="Decrypt a file using X25519. Requires private key, public key, and encrypted file.")

        self.parser.add_argument('--simulate_sign_ed25519', nargs=3,
                                 metavar=('PUBLIC_KEY_PATH', 'FILE_PATH', 'OUTPUT_SIG'),
                                 help="Simulate signing a file using Ed25519 public key (not secure)")

        self.parser.add_argument('--simulate_verify_ed25519', nargs=3,
                                 metavar=('PUBLIC_KEY_PATH', 'FILE_PATH', 'INPUT_SIG'),
                                 help="Simulate verifying a fake Ed25519 signature (not secure)")


        # Command for signing a file
        self.parser.add_argument('--sign', action='store_true', help="Sign a file with the private key (RSA)")
        self.parser.add_argument('--sign_file_RSA', help="Sign a file with RSA private key", nargs=3, metavar=('PRIVATE_KEY_PATH', 'FILE_PATH', 'SIGNATURE_OUTPUT_PATH'))

        self.parser.add_argument('--verify', action='store_true', help="Verify a file's signature with the public key (RSA)")
        # File paths and RSA key paths
        self.parser.add_argument('--private_key', type=str, help="Path to the private key file for signing")
        self.parser.add_argument('--public_key', type=str, help="Path to the public key file for verification")
        self.parser.add_argument('--file', type=str, help="Path to the file to be signed or verified")
        self.parser.add_argument('--signature', type=str, help="Path to the signature file for verification")
        self.parser.add_argument('--signature_output', type=str, help="Path to save the signature when signing")
        self.parser.add_argument('--generate_x25519_keys', help="Generate X25519 key pair", nargs=2, metavar=('PRIVATE_KEY_PATH', 'PUBLIC_KEY_PATH'))

        self.parser.add_argument(
            "--load-private-key", "-lp",
            help="Specify the filename to load the private key from"
        )
        self.parser.add_argument(
            "--load-public-key", "-lu",
            help="Specify the filename to load the public key from"
        )
        self.parser.add_argument(
            "--keypair", "-k", action="store_true",
            help="Generate both public and private keys (for RSA/Ed25519)"
        )

        self.parser.add_argument(
            "--encrypt-file-RSA", "-efr",
            help="Specify the filename to encrypt using the RSA private key"
        )
        self.parser.add_argument(
            "--decrypt-file-RSA", "-dfr",
            help="Specify the filename to decrypt using the RSA public key"
        )
        self.parser.add_argument(
            "--output-file", "-o",
            help="Specify the RSA filename for saving the output (encrypted or decrypted)"
        )

        # Arguments specific to X25519 encryption/decryption
        self.parser.add_argument(
            "--sender-private-key", "-sp",
            help="Specify the filename of the sender's private key (X25519)"
        )
        self.parser.add_argument(
            "--recipient-public-key", "-rp",
            help="Specify the filename of the recipient's public key (X25519)"
        )
        # Ed25519 signing and verifying
        self.parser.add_argument('--sign_file_ed25519', help="Sign a file with Ed25519 private key", nargs=3, metavar=('PRIVATE_KEY_PATH', 'FILE_PATH', 'SIGNATURE_OUTPUT_PATH'))
        self.parser.add_argument('--verify_ed25519', help="Verify a file's signature with Ed25519 public key", nargs=3, metavar=('PUBLIC_KEY_PATH', 'FILE_PATH', 'SIGNATURE_PATH'))

        args = self.parser.parse_args()

        key_manager = KeyManager(algorithm="RSA")

        # Sign a file
        if args.sign:
            if not all([args.private_key, args.file, args.signature_output]):
                print("Error: Missing required arguments for signing.")
                return
            key_manager.sign_file_RSA(args.private_key, args.file, args.signature_output)

        # Verify a file's signature
        if args.verify:
            if not all([args.public_key, args.file, args.signature]):
                print("Error: Missing required arguments for verification.")
            else:
                key_manager.verify_signature_RSA(args.public_key, args.file, args.signature)

    def parse_arguments(self):
        return self.parser.parse_args()



if __name__ == "__main__":
    cli = CommandLineInterface()
    args = cli.parse_arguments()

    # Initialize KeyManager
    key_manager = KeyManager(args.algorithm, args.keypair)

    try:

        # Simulate Ed25519 "signing" using public key
        if args.simulate_sign_ed25519:
            public_key_path, file_path, output_sig = args.simulate_sign_ed25519
            key_manager.simulate_sign_with_public_key_ed25519(public_key_path, file_path, output_sig)

        # Simulate Ed25519 "verification"
        if args.simulate_verify_ed25519:
            public_key_path, file_path, input_sig = args.simulate_verify_ed25519
            key_manager.simulate_verify_with_public_key_ed25519(public_key_path, file_path, input_sig)


        # Only generate keys if keypair flag is passed
        if args.keypair and not (args.load_private_key or args.load_public_key):
            result = key_manager.generate_key()
            print(result)


        # Handle X25519 Key Pair Generation
        if args.generate_x25519_keys:
            private_key_path, public_key_path = args.generate_x25519_keys
            key_manager.generate_x25519_keys_and_save(private_key_path, public_key_path)

        # Handle X25519 Encryption
        elif args.encrypt_file_X25519:
            private_key_path, public_key_path, input_file = args.encrypt_file_X25519
            sender_private_key = key_manager.load_x25519_private_key(private_key_path)
            recipient_public_key = key_manager.load_x25519_public_key(public_key_path)

            output_file = input_file + ".enc"
            key_manager.encrypt_file(sender_private_key, recipient_public_key, input_file, output_file)
            print(f"X25519 Encrypted: {input_file} → {output_file}")

        # Handle X25519 Decryption
        elif args.decrypt_file_X25519:
            private_key_path, public_key_path, encrypted_file = args.decrypt_file_X25519
            recipient_private_key = key_manager.load_x25519_private_key(private_key_path)
            sender_public_key = key_manager.load_x25519_public_key(public_key_path)

            output_file = encrypted_file.replace(".enc", ".dec")
            key_manager.decrypt_file(recipient_private_key, sender_public_key, encrypted_file, output_file)
            print(f"X25519 Decrypted: {encrypted_file} → {output_file}")

        # RSA File Encryption
        if args.encrypt_file_RSA and args.output_file and args.load_public_key:
            public_key = key_manager.load_public_key(args.load_public_key)
            key_manager.encrypt_file_with_public_key_RSA(public_key, args.encrypt_file_RSA, args.output_file)
            print(f"RSA File encrypted: {args.encrypt_file_RSA} → {args.output_file}")

        # RSA File Decryption
        elif args.decrypt_file_RSA and args.output_file and args.load_private_key:
            private_key = key_manager.load_private_key(args.load_private_key)
            key_manager.decrypt_file_with_private_key_RSA(private_key, args.decrypt_file_RSA, args.output_file)
            print(f"RSA File decrypted: {args.decrypt_file_RSA} → {args.output_file}")

        # X25519 File Encryption
        elif args.encrypt_file_X25519 and args.output_file and args.sender_private_key and args.recipient_public_key:
            with open(args.sender_private_key, "rb") as f:
                sender_private_key = x25519.X25519PrivateKey.from_private_bytes(f.read())

            with open(args.recipient_public_key, "rb") as f:
                recipient_public_key = x25519.X25519PublicKey.from_public_bytes(f.read())

            key_manager.encrypt_file(sender_private_key, recipient_public_key, args.encrypt_file_X25519, args.output_file)
            print(f"X25519 File encrypted: {args.encrypt_file_X25519} → {args.output_file}")

        # X25519 File Decryption
        elif args.decrypt_file_X25519 and args.output_file and args.recipient_private_key and args.sender_public_key:
            with open(args.recipient_private_key, "rb") as f:
                recipient_private_key = x25519.X25519PrivateKey.from_private_bytes(f.read())

            with open(args.sender_public_key, "rb") as f:
                sender_public_key = x25519.X25519PublicKey.from_public_bytes(f.read())

            key_manager.decrypt_file(recipient_private_key, sender_public_key, args.decrypt_file_X25519, args.output_file)
            print(f"X25519 File decrypted: {args.decrypt_file_X25519} → {args.output_file}")

        # Encrypt with RSA private key
        if args.encrypt_with_private_RSA:
            private_key_path, input_file, output_file = args.encrypt_with_private_RSA
            private_key = key_manager.load_private_key(private_key_path)
            key_manager.encrypt_file_with_private_key_RSA(private_key, input_file, output_file)

        # Decrypt with RSA public key
        if args.decrypt_with_public_RSA:
            public_key_path, encrypted_file, output_file = args.decrypt_with_public_RSA
            public_key = key_manager.load_public_key(public_key_path)
            key_manager.decrypt_file_with_public_key_RSA(public_key, encrypted_file, output_file)


        # Load Private Key
        if args.load_private_key:
            private_key = key_manager.load_private_key(args.load_private_key)
            print("Private key loaded from file:", args.load_private_key)

        # Load Public Key
        if args.load_public_key:
            public_key = key_manager.load_public_key(args.load_public_key)
            print("Public key loaded from file:", args.load_public_key)

        # Load Ed25519 Private Key
        if args.algorithm == "Ed25519" and args.load_private_key:
            private_key = key_manager.load_ed25519_private_key(args.load_private_key)
            print("Ed25519 Private key loaded from file:", args.load_private_key)

        # Load Ed25519 Public Key
        if args.algorithm == "Ed25519" and args.load_public_key:
            public_key = key_manager.load_ed25519_public_key(args.load_public_key)
            print("Ed25519 Public key loaded from file:", args.load_public_key)

        # Only generate keys when explicitly asked
        if args.keypair:
            result = key_manager.generate_key()
            print(result)

        # Handle RSA File Signing
        if args.sign_file_RSA:
            private_key_path, file_path, signature_output_path = args.sign_file_RSA
            key_manager.sign_file_RSA(private_key_path, file_path, signature_output_path)
            print(f"File {file_path} signed and signature saved to {signature_output_path}")

        # Ed25519: Sign file
        if args.sign_file_ed25519:
            private_key_path, file_path, signature_output_path = args.sign_file_ed25519
            key_manager = KeyManager(algorithm="Ed25519")
            key_manager.sign_file_ed25519(private_key_path, file_path, signature_output_path)

        # Ed25519: Verify file
        if args.verify_ed25519:
            public_key_path, file_path, signature_path = args.verify_ed25519
            key_manager = KeyManager(algorithm="Ed25519")
            key_manager.verify_signature_ed25519(public_key_path, file_path, signature_path)


    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")