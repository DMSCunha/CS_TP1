# SGX E-Wallet - Secure Credential Manager

This is a secure electronic wallet (e-wallet) application built using Intel SGX (Software Guard Extensions) technology for storing and managing up to 100 login credentials securely.

## Features

- **Secure Storage**: All credentials are encrypted using AES-GCM 128-bit encryption inside the SGX enclave
- **Master Password Protection**: Access to the wallet is protected by a master password (8-100 characters)
- **SGX Sealing**: Encrypted data is sealed using SGX sealing for persistent storage
- **Secure Password Generation**: Generate cryptographically secure random passwords (8-100 characters)
- **Minimized TCB**: Only sensitive cryptographic operations run inside the enclave

## Security Architecture

1. **Enclave Operations** (Trusted):
   - AES-GCM encryption/decryption
   - Master password key derivation (SHA-256)
   - Secure random password generation
   - Data sealing/unsealing

2. **Application Operations** (Untrusted):
   - User interface
   - File I/O operations
   - Command-line parsing

## Building

```bash
make
```

This will build the application in simulation mode by default. The binary will be in `application/bin/app`.

## Usage

### Create a new wallet
```bash
./application/bin/app -p <master-password> -n
```

### Show wallet contents
```bash
./application/bin/app -p <master-password> -s
```

### Add a credential
```bash
./application/bin/app -p <master-password> -a -x <title> -y <username> -z <password>
```

### Remove a credential
```bash
./application/bin/app -p <master-password> -r <item-index>
```

### Change master password
```bash
./application/bin/app -p <old-password> -c <new-password>
```

### Generate a secure random password
```bash
./application/bin/app -g -l <length>
```
(length must be between 8 and 100)

### Help
```bash
./application/bin/app -h
```

## File Structure

- `application/` - Untrusted application code
- `enclave/` - Trusted enclave code
- `enclave/conf/enclave.edl` - Enclave definition with ECALLs
- `ewallet.db` - Encrypted and sealed wallet database file

## Security Notes

- The master password is used to derive an AES-128 encryption key via SHA-256
- All wallet data is encrypted inside the enclave before being sealed
- The sealed data includes: IV (12 bytes) + MAC (16 bytes) + encrypted wallet
- Password verification is done by attempting decryption; MAC verification ensures integrity
- Sensitive data (keys, passwords) are cleared from memory after use

## Requirements

- Intel SGX SDK
- SGX-capable CPU (or simulation mode)
- Linux operating system

## Limitations

- Maximum 100 credentials
- Each field (title, username, password) limited to 100 characters
- Master password must be 8-100 characters


application/bin/ewallet.sh -p testpass123 -n        # create wallet
application/bin/ewallet.sh -p testpass123 -s        # show wallet
application/bin/ewallet.sh -g -l 12                 # generate password
application/bin/ewallet.sh -p testpass123 -a -x example -y alice -z s3cr3t
application/bin/ewallet.sh -p testpass123 -r 0
application/bin/ewallet.sh -p testpass123 -c newpass456