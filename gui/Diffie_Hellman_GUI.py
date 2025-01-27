from Diffie_Hellman_Key_Exchange.DiffieHellmanKeyExchange import DiffieHellmanKeyExchange
from Diffie_Hellman_Attack.DiffieHellmanAttack import meet_in_the_middle_attack

from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                           QPushButton, QLabel, QLineEdit, QTextEdit, QSpinBox,
                           QGroupBox, QMessageBox, QTabWidget,QProgressBar)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QPalette, QColor
import hashlib

class AttackThread(QThread):
    finished = pyqtSignal(tuple)
    progress = pyqtSignal(int)
    
    def __init__(self, prime, generator, public_key_a, public_key_b):
        super().__init__()
        self.prime = prime
        self.generator = generator
        self.public_key_a = public_key_a
        self.public_key_b = public_key_b
        
    def run(self):
        known_values = {}
        total_iterations = 2**16
        
        # First phase
        for private_key in range(1, 2**16):
            public_key_a = pow(self.generator, private_key, self.prime)
            known_values[public_key_a] = private_key
            if private_key % 100 == 0:
                self.progress.emit(int(private_key / total_iterations * 50))
                
        # Second phase
        for private_key in range(1, 2**16):
            public_key_b = pow(self.generator, private_key, self.prime)
            if public_key_b in known_values:
                shared_secret_a = pow(self.public_key_a, private_key, self.prime)
                shared_secret_b = pow(self.public_key_b, private_key, self.prime)
                hashed_secret_a = hashlib.sha256(str(shared_secret_a).encode()).digest()
                hashed_secret_b = hashlib.sha256(str(shared_secret_b).encode()).digest()
                self.finished.emit((hashed_secret_a, hashed_secret_b))
                return
            if private_key % 100 == 0:
                self.progress.emit(50 + int(private_key / total_iterations * 50))

class DiffieHellmanGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.dh_alice = None
        self.dh_bob = None
        self.attack_thread = None
        self.initUI()
        
    def initUI(self):
        self.setWindowTitle('Diffie-Hellman Key Exchange Simulator')
        self.setMinimumSize(1000, 700)
        
        # Set the window style
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f0f0f0;
            }
            QGroupBox {
                background-color: white;
                border-radius: 8px;
                margin-top: 10px;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 8px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
            QPushButton:disabled {
                background-color: #BDBDBD;
            }
            QLineEdit, QSpinBox {
                padding: 6px;
                border: 1px solid #BDBDBD;
                border-radius: 4px;
            }
            QTextEdit {
                border: 1px solid #BDBDBD;
                border-radius: 4px;
            }
            QProgressBar {
                border: 1px solid #BDBDBD;
                border-radius: 4px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #2196F3;
            }
        """)

        # Create central widget and tab widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        tab_widget = QTabWidget()
        
        # Create tabs
        key_exchange_tab = QWidget()
        attack_tab = QWidget()
        
        tab_widget.addTab(key_exchange_tab, "Key Exchange")
        tab_widget.addTab(attack_tab, "Meet-in-the-Middle Attack")
        
        # Set up Key Exchange tab
        key_exchange_layout = QVBoxLayout(key_exchange_tab)
        
        # Parameters Group
        params_group = QGroupBox("System Parameters")
        params_layout = QHBoxLayout()
        
        # Prime bits input
        prime_layout = QVBoxLayout()
        prime_label = QLabel("Prime Number Bits:")
        self.prime_bits = QSpinBox()
        self.prime_bits.setRange(128, 2048)
        self.prime_bits.setValue(512)
        self.prime_bits.setSingleStep(128)
        prime_layout.addWidget(prime_label)
        prime_layout.addWidget(self.prime_bits)
        
        # Generator input
        generator_layout = QVBoxLayout()
        generator_label = QLabel("Generator:")
        self.generator_input = QLineEdit()
        self.generator_input.setText("2")
        generator_layout.addWidget(generator_label)
        generator_layout.addWidget(self.generator_input)
        
        params_layout.addLayout(prime_layout)
        params_layout.addLayout(generator_layout)
        params_group.setLayout(params_layout)
        
        # Initialize button
        self.init_button = QPushButton("Initialize System")
        self.init_button.clicked.connect(self.initialize_system)
        
        # Keys Group
        keys_group = QGroupBox("Generated Keys")
        keys_layout = QVBoxLayout()
        
        # Alice's keys
        alice_layout = QHBoxLayout()
        alice_layout.addWidget(QLabel("Alice's Public Key:"))
        self.alice_public = QLineEdit()
        self.alice_public.setReadOnly(True)
        alice_layout.addWidget(self.alice_public)
        
        # Bob's keys
        bob_layout = QHBoxLayout()
        bob_layout.addWidget(QLabel("Bob's Public Key:"))
        self.bob_public = QLineEdit()
        self.bob_public.setReadOnly(True)
        bob_layout.addWidget(self.bob_public)
        
        keys_layout.addLayout(alice_layout)
        keys_layout.addLayout(bob_layout)
        keys_group.setLayout(keys_layout)
        
        # Shared Secrets Group
        secrets_group = QGroupBox("Computed Shared Secrets")
        secrets_layout = QVBoxLayout()
        
        # Compute button
        self.compute_button = QPushButton("Compute Shared Secrets")
        self.compute_button.clicked.connect(self.compute_secrets)
        self.compute_button.setEnabled(False)
        
        # Secret displays
        self.alice_secret = QTextEdit()
        self.alice_secret.setReadOnly(True)
        self.alice_secret.setMaximumHeight(60)
        self.bob_secret = QTextEdit()
        self.bob_secret.setReadOnly(True)
        self.bob_secret.setMaximumHeight(60)
        
        secrets_layout.addWidget(QLabel("Alice's Computed Secret:"))
        secrets_layout.addWidget(self.alice_secret)
        secrets_layout.addWidget(QLabel("Bob's Computed Secret:"))
        secrets_layout.addWidget(self.bob_secret)
        secrets_group.setLayout(secrets_layout)
        
        # Add components to key exchange tab
        key_exchange_layout.addWidget(params_group)
        key_exchange_layout.addWidget(self.init_button)
        key_exchange_layout.addWidget(keys_group)
        key_exchange_layout.addWidget(self.compute_button)
        key_exchange_layout.addWidget(secrets_group)
        
        # Set up Attack tab
        attack_layout = QVBoxLayout(attack_tab)
        
        # Attack Parameters Group
        attack_params_group = QGroupBox("Attack Parameters")
        attack_params_layout = QVBoxLayout()
        
        # Prime and generator inputs
        attack_prime_layout = QHBoxLayout()
        attack_prime_layout.addWidget(QLabel("Prime:"))
        self.attack_prime = QLineEdit()
        attack_prime_layout.addWidget(self.attack_prime)
        
        attack_generator_layout = QHBoxLayout()
        attack_generator_layout.addWidget(QLabel("Generator:"))
        self.attack_generator = QLineEdit()
        attack_generator_layout.addWidget(self.attack_generator)
        
        # Public key inputs
        attack_public_a_layout = QHBoxLayout()
        attack_public_a_layout.addWidget(QLabel("Target Public Key A:"))
        self.attack_public_a = QLineEdit()
        attack_public_a_layout.addWidget(self.attack_public_a)
        
        attack_public_b_layout = QHBoxLayout()
        attack_public_b_layout.addWidget(QLabel("Target Public Key B:"))
        self.attack_public_b = QLineEdit()
        attack_public_b_layout.addWidget(self.attack_public_b)
        
        # Use current values button
        self.use_current_button = QPushButton("Use Current System Values")
        self.use_current_button.clicked.connect(self.use_current_values)
        
        # Start attack button
        self.start_attack_button = QPushButton("Start Attack")
        self.start_attack_button.clicked.connect(self.start_attack)
        
        # Progress bar
        self.attack_progress = QProgressBar()
        self.attack_progress.setMaximum(100)
        
        # Results display
        attack_results_group = QGroupBox("Attack Results")
        attack_results_layout = QVBoxLayout()
        
        self.attack_result_a = QTextEdit()
        self.attack_result_a.setReadOnly(True)
        self.attack_result_a.setMaximumHeight(60)
        
        self.attack_result_b = QTextEdit()
        self.attack_result_b.setReadOnly(True)
        self.attack_result_b.setMaximumHeight(60)
        
        attack_results_layout.addWidget(QLabel("Discovered Secret A:"))
        attack_results_layout.addWidget(self.attack_result_a)
        attack_results_layout.addWidget(QLabel("Discovered Secret B:"))
        attack_results_layout.addWidget(self.attack_result_b)
        attack_results_group.setLayout(attack_results_layout)
        
        # Add components to attack parameters group
        attack_params_layout.addLayout(attack_prime_layout)
        attack_params_layout.addLayout(attack_generator_layout)
        attack_params_layout.addLayout(attack_public_a_layout)
        attack_params_layout.addLayout(attack_public_b_layout)
        attack_params_group.setLayout(attack_params_layout)
        
        # Add components to attack tab
        attack_layout.addWidget(attack_params_group)
        attack_layout.addWidget(self.use_current_button)
        attack_layout.addWidget(self.start_attack_button)
        attack_layout.addWidget(self.attack_progress)
        attack_layout.addWidget(attack_results_group)
        
        # Add tab widget to main layout
        main_layout.addWidget(tab_widget)
        
    def initialize_system(self):
        try:
            prime_bits = self.prime_bits.value()
            generator = int(self.generator_input.text())
            
            # Initialize Alice and Bob's DH instances
            self.dh_alice = DiffieHellmanKeyExchange()
            self.dh_bob = DiffieHellmanKeyExchange(prime=self.dh_alice.prime, generator=generator)
            
            # Display public keys
            self.alice_public.setText(str(self.dh_alice.public_key))
            self.bob_public.setText(str(self.dh_bob.public_key))
            
            # Enable compute button
            self.compute_button.setEnabled(True)
            
            QMessageBox.information(self, "Success", "System initialized successfully!")
            
        except ValueError as e:
            QMessageBox.critical(self, "Error", f"Invalid input: {str(e)}")
            
    def compute_secrets(self):
        if not self.dh_alice or not self.dh_bob:
            return
            
        # Compute shared secrets
        alice_secret = self.dh_alice.compute_shared_secret(self.dh_bob.public_key)
        bob_secret = self.dh_bob.compute_shared_secret(self.dh_alice.public_key)
        
        # Display secrets in hex format
        self.alice_secret.setText(alice_secret.hex())
        self.bob_secret.setText(bob_secret.hex())
        
        # Verify if secrets match
        if alice_secret == bob_secret:
            QMessageBox.information(self, "Success", "Shared secrets match! Secure communication can begin.")
        else:
            QMessageBox.warning(self, "Warning", "Shared secrets do not match!")
            
    def use_current_values(self):
        if not self.dh_alice or not self.dh_bob:
            QMessageBox.warning(self, "Warning", "Please initialize the system first!")
            return
            
        self.attack_prime.setText(str(self.dh_alice.prime))
        self.attack_generator.setText(str(self.dh_alice.generator))
        self.attack_public_a.setText(str(self.dh_alice.public_key))
        self.attack_public_b.setText(str(self.dh_bob.public_key))
        
    def start_attack(self):
        try:
            prime = int(self.attack_prime.text())
            generator = int(self.attack_generator.text())
            public_key_a = int(self.attack_public_a.text())
            public_key_b = int(self.attack_public_b.text())
            
            # Create and start attack thread
            self.attack_thread = AttackThread(prime, generator, public_key_a, public_key_b)
            self.attack_thread.finished.connect(self.attack_finished)
            self.attack_thread.progress.connect(self.attack_progress.setValue)
            
            # Disable buttons during attack
            self.start_attack_button.setEnabled(False)
            self.use_current_button.setEnabled(False)
            
            # Clear previous results
            self.attack_result_a.clear()
            self.attack_result_b.clear()
            
            # Start attack
            self.attack_thread.start()
            
        except ValueError as e:
            QMessageBox.critical(self, "Error", f"Invalid input: {str(e)}")
    def attack_finished(self, results):
        secret_a, secret_b = results
        
        # Display results
        self.attack_result_a.setText(secret_a.hex())
        self.attack_result_b.setText(secret_b.hex())
        
        # Compare with actual secrets if available
        if self.dh_alice and self.dh_bob:
            actual_secret_a = self.dh_alice.compute_shared_secret(self.dh_bob.public_key)
            actual_secret_b = self.dh_bob.compute_shared_secret(self.dh_alice.public_key)
            
            if secret_a == actual_secret_a and secret_b == actual_secret_b:
                QMessageBox.information(self, "Attack Success", 
                    "Attack successful! The discovered secrets match the actual shared secrets.")
            else:
                QMessageBox.warning(self, "Attack Result", 
                    "Attack completed, but the discovered secrets don't match the actual secrets.")
        else:
            QMessageBox.information(self, "Attack Completed", 
                "Attack completed. Discovered potential secrets are displayed.")
        
        # Re-enable buttons
        self.start_attack_button.setEnabled(True)
        self.use_current_button.setEnabled(True)
        
        # Reset progress bar
        self.attack_progress.setValue(0)