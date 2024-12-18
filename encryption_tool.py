import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QLabel, QLineEdit, QPushButton, QTextEdit,
    QVBoxLayout, QHBoxLayout, QWidget, QFileDialog, QMessageBox, QTabWidget
)
from cryptography.fernet import Fernet
import rsa


class EncryptionTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Encryption Tool")
        self.setGeometry(200, 100, 800, 600)

        # Initialize tabs
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        # AES Tab
        self.aes_tab = QWidget()
        self.init_aes_tab()
        self.tabs.addTab(self.aes_tab, "AES Encryption")

        # RSA Tab
        self.rsa_tab = QWidget()
        self.init_rsa_tab()
        self.tabs.addTab(self.rsa_tab, "RSA Encryption")

    def init_aes_tab(self):
        layout = QVBoxLayout()

        # AES Key Generation
        layout.addWidget(QLabel("AES Key Management"))
        self.aes_generate_btn = QPushButton("Generate AES Key")
        self.aes_generate_btn.clicked.connect(self.generate_aes_key)
        layout.addWidget(self.aes_generate_btn)

        # Input for AES Encryption/Decryption
        layout.addWidget(QLabel("Input Text/File for Encryption/Decryption"))
        self.aes_input = QTextEdit()
        layout.addWidget(self.aes_input)

        # Buttons for AES Encryption/Decryption
        btn_layout = QHBoxLayout()
        self.aes_encrypt_btn = QPushButton("Encrypt")
        self.aes_encrypt_btn.clicked.connect(self.aes_encrypt)
        btn_layout.addWidget(self.aes_encrypt_btn)

        self.aes_decrypt_btn = QPushButton("Decrypt")
        self.aes_decrypt_btn.clicked.connect(self.aes_decrypt)
        btn_layout.addWidget(self.aes_decrypt_btn)

        layout.addLayout(btn_layout)

        # Output
        layout.addWidget(QLabel("Output"))
        self.aes_output = QTextEdit()
        self.aes_output.setReadOnly(True)
        layout.addWidget(self.aes_output)

        self.aes_tab.setLayout(layout)

    def init_rsa_tab(self):
        layout = QVBoxLayout()

        # RSA Key Management
        layout.addWidget(QLabel("RSA Key Management"))
        self.rsa_generate_btn = QPushButton("Generate RSA Keys")
        self.rsa_generate_btn.clicked.connect(self.generate_rsa_keys)
        layout.addWidget(self.rsa_generate_btn)

        # Input for RSA Encryption/Decryption
        layout.addWidget(QLabel("Input Text/File for Encryption/Decryption"))
        self.rsa_input = QTextEdit()
        layout.addWidget(self.rsa_input)

        # Buttons for RSA Encryption/Decryption
        btn_layout = QHBoxLayout()
        self.rsa_encrypt_btn = QPushButton("Encrypt")
        self.rsa_encrypt_btn.clicked.connect(self.rsa_encrypt)
        btn_layout.addWidget(self.rsa_encrypt_btn)

        self.rsa_decrypt_btn = QPushButton("Decrypt")
        self.rsa_decrypt_btn.clicked.connect(self.rsa_decrypt)
        btn_layout.addWidget(self.rsa_decrypt_btn)

        layout.addLayout(btn_layout)

        # Output
        layout.addWidget(QLabel("Output"))
        self.rsa_output = QTextEdit()
        self.rsa_output.setReadOnly(True)
        layout.addWidget(self.rsa_output)

        self.rsa_tab.setLayout(layout)

    # AES Key Management
    def generate_aes_key(self):
        key = Fernet.generate_key()
        with open("aes_key.key", "wb") as key_file:
            key_file.write(key)
        self.aes_output.append("AES Key generated and saved as aes_key.key")

    def load_aes_key(self):
        try:
            with open("aes_key.key", "rb") as key_file:
                return key_file.read()
        except FileNotFoundError:
            QMessageBox.warning(self, "Error", "AES Key not found. Generate it first.")
            return None

    # AES Encryption
    def aes_encrypt(self):
        key = self.load_aes_key()
        if key:
            fernet = Fernet(key)
            plaintext = self.aes_input.toPlainText().encode()
            ciphertext = fernet.encrypt(plaintext)
            self.aes_output.append(f"Encrypted Text: {ciphertext.decode()}")

    # AES Decryption
    def aes_decrypt(self):
        key = self.load_aes_key()
        if key:
            fernet = Fernet(key)
            ciphertext = self.aes_input.toPlainText().encode()
            try:
                plaintext = fernet.decrypt(ciphertext)
                self.aes_output.append(f"Decrypted Text: {plaintext.decode()}")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Decryption failed: {str(e)}")

    # RSA Key Management
    def generate_rsa_keys(self):
        public_key, private_key = rsa.newkeys(2048)
        with open("rsa_public.pem", "wb") as pub_file:
            pub_file.write(public_key.save_pkcs1())
        with open("rsa_private.pem", "wb") as priv_file:
            priv_file.write(private_key.save_pkcs1())
        self.rsa_output.append("RSA Keys generated and saved.")

    def load_rsa_keys(self):
        try:
            with open("rsa_public.pem", "rb") as pub_file:
                public_key = rsa.PublicKey.load_pkcs1(pub_file.read())
            with open("rsa_private.pem", "rb") as priv_file:
                private_key = rsa.PrivateKey.load_pkcs1(priv_file.read())
            return public_key, private_key
        except FileNotFoundError:
            QMessageBox.warning(self, "Error", "RSA Keys not found. Generate them first.")
            return None, None

    # RSA Encryption
    def rsa_encrypt(self):
        public_key, _ = self.load_rsa_keys()
        if public_key:
            plaintext = self.rsa_input.toPlainText().encode()
            ciphertext = rsa.encrypt(plaintext, public_key)
            with open("rsa_ciphertext.bin", "wb") as file:
                file.write(ciphertext)
            self.rsa_output.append("Encrypted text saved to rsa_ciphertext.bin")

    # RSA Decryption
    def rsa_decrypt(self):
        _, private_key = self.load_rsa_keys()
        if private_key:
            try:
                with open("rsa_ciphertext.bin", "rb") as file:
                    ciphertext = file.read()
                plaintext = rsa.decrypt(ciphertext, private_key).decode()
                self.rsa_output.append(f"Decrypted Text: {plaintext}")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Decryption failed: {str(e)}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = EncryptionTool()
    window.show()
    sys.exit(app.exec())