# Diffie-Hellman Key Exchange Simulator
A graphical user interface application that demonstrates the Diffie-Hellman key exchange protocol and includes a meet-in-the-middle attack simulation. This educational tool helps understand both the protocol's implementation and its potential vulnerabilities.
## Features
### Key Exchange Simulation 

o	Generate prime numbers with configurable bit length

o	Set custom generator values

o	View public keys for both parties

o	Compute and verify shared secrets

o	Real-time validation of key matching

### Meet-in-the-Middle Attack Simulation 

o	Input custom parameters or use current system values

o	Real-time attack progress monitoring

o	Visual representation of discovered secrets

o	Automatic verification against actual secrets

o	Non-blocking attack execution

## Installation:
### Install required packages:
pip install -r requirements.txt

### Run the application:
python main.py

### Key Exchange Tab: 

•	Set the desired prime number bits (128-2048)

•	Set the generator value (default is 2)

•	Click "Initialize System" to generate keys

•	Click "Compute Shared Secrets" to see the results

### Attack Simulation Tab:

•	Enter prime, generator, and public key values manually

•	Or click "Use Current System Values" to use values from the Key Exchange tab

•	Click "Start Attack" to begin the simulation

•	Monitor progress and view results

### You can also use the app without GUI. (check out “testing…” folder)
