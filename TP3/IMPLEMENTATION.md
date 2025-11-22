# SGX E-Wallet Implementation Details

## Architecture Overview

This implementation follows a security-first design where all sensitive operations are performed inside the SGX enclave to minimize the Trusted Computing Base (TCB).

## Trusted Components (Inside Enclave)

### 1. Cryptographic Operations

**AES-GCM Encryption (`ecall_encrypt_wallet`)**
- Derives 128-bit AES key from master password using SHA-256
- Generates random 12-byte IV using `sgx_read_rand`
- Encrypts wallet data using AES-GCM-128
- Returns ciphertext, IV, and 16-byte MAC tag
- Clears key from memory after use

**AES-GCM Decryption (`ecall_decrypt_wallet`)**
- Derives decryption key from master password
- Decrypts ciphertext using provided IV and MAC
- MAC verification ensures both authenticity and integrity
- Returns error if password is wrong or data is tampered

**Key Derivation**
- Uses SHA-256 to hash master password
- First 16 bytes of hash used as AES-128 key
- Deterministic: same password always produces same key

### 2. Password Operations

**Secure Random Password Generation (`ecall_generate_password`)**
- Uses `sgx_read_rand` for cryptographically secure randomness
- Character set includes: a-z, A-Z, 0-9, and special characters
- Length configurable between 8-100 characters
- No bias in character selection

**Password Verification (`ecall_verify_password`)**
- Attempts to decrypt wallet with provided password
- Success means password is correct
- Failure means wrong password or corrupted data

### 3. Sealing Operations

**Sealing (`ecall_seal_data`)**
- Uses SGX sealing to protect data at rest
- Sealed data can only be unsealed by same enclave on same platform
- Provides additional hardware-based protection layer

**Unsealing (`ecall_unseal_data`)**
- Recovers encrypted wallet from sealed data
- Verifies seal integrity

## Untrusted Components (Outside Enclave)

### 1. File Operations

**Save Wallet**
1. Calls enclave to encrypt wallet with master password
2. Calls enclave to seal encrypted data
3. Writes to file: [IV][MAC][sealed_encrypted_data]

**Load Wallet**
1. Reads IV, MAC, and sealed data from file
2. Calls enclave to unseal encrypted data
3. Calls enclave to decrypt with master password
4. Returns plaintext wallet

### 2. User Interface
- Command-line argument parsing
- Input validation
- Output formatting
- Help messages

### 3. Wallet Management
- Creating new wallet
- Adding/removing credentials
- Changing master password
- Displaying wallet contents

## Security Properties

### Confidentiality
1. **Master password never stored** - only used to derive encryption key
2. **Encryption inside enclave** - plaintext never exposed to untrusted code
3. **AES-GCM encryption** - industry-standard authenticated encryption
4. **SGX sealing** - hardware-protected sealed storage

### Integrity
1. **MAC verification** - detects any tampering with encrypted data
2. **Seal integrity** - SGX verifies sealed data hasn't been modified
3. **Password verification** - decryption fails if password is wrong

### Availability
1. **Persistent storage** - wallet survives application restarts
2. **Error handling** - graceful failure on corruption or wrong password

## Data Flow

### Creating Wallet
```
User Input → Validate → Create Wallet Structure →
Enclave: Encrypt → Enclave: Seal → Write File
```

### Loading Wallet
```
Read File → Enclave: Unseal → Enclave: Decrypt →
Verify Password → Return Wallet
```

### Adding Credential
```
Load Wallet → Verify Password → Add Item →
Enclave: Encrypt → Enclave: Seal → Write File
```

## TCB Minimization

Only the following operations run in the enclave:
- Key derivation (SHA-256)
- Encryption/Decryption (AES-GCM)
- Random number generation
- Sealing/Unsealing

Everything else runs in untrusted code:
- File I/O
- Memory allocation (for untrusted buffers)
- User interface
- Business logic (adding/removing items)

This minimizes the attack surface and reduces the amount of code that needs to be trusted.

## File Format

**ewallet.db Structure:**
```
[IV - 12 bytes]
[MAC - 16 bytes]
[Sealed Encrypted Wallet - variable size]
```

The sealed encrypted wallet contains the AES-GCM encrypted version of the wallet structure, which includes:
- Array of up to 100 credentials (title, username, password)
- Number of credentials
- Master password (for internal verification)

## Threat Model

### Protected Against:
- Memory dumps of untrusted process (data is encrypted)
- File system access by attacker (data is sealed and encrypted)
- Wrong password attempts (MAC verification)
- Data tampering (MAC verification)
- Cold boot attacks (keys never in untrusted memory)

### Not Protected Against:
- Enclave side-channel attacks (out of scope)
- Compromised SGX hardware (out of scope)
- User giving master password to attacker (user error)
- Attacks while data is decrypted inside enclave (enclave memory protected by SGX)

## Compliance

This implementation meets the project requirements:
1. ✓ Manages up to 100 credentials
2. ✓ Each credential has title, username, password (max 100 chars each)
3. ✓ Master password protection (8-100 chars)
4. ✓ AES-GCM 128-bit encryption
5. ✓ SGX sealing for persistence
6. ✓ Create, show, add, remove, password generation operations
7. ✓ Minimized TCB
8. ✓ All sensitive operations in enclave
