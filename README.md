# Hashing CLI Application

**NOTE**: *As this is a public repository for a school project we ask that you never copy our code or promote it without credit to us and the university*.


## 🚀 Launching The Application

In order to run the application, 
1. Open Terminal and Navigate to where you want to download this application
3. Copy the following and paste it into your terminal and enjoy encrypting!
```bash
git clone https://github.com/BenjuhminStewart/cryptography-project.git
cd cryptography-project
cd tcss487
cd src
javac *.java
java Hash.java
```

## 🔧 Features

1. cSHAKE256
2. KMACXOF256
3. KMAC256
4. KECCAK *f*

## Commands

- `symm`: Encrypt/Decrypt a file symmetrically using a passphrase.
- `auth`: Computes an authentication tag (MAC) of a given file under a given passphrase.
- `kmac`: Compute cryptographic hash
- `ec`: Elliptic curve functions
- `help`: List all commands
- `exit`: Exit the program
