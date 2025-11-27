# BIP-39 Seed Phrase Encryptor with Shamir Secret Sharing

A cryptographically secure tool for encrypting BIP-39 seed phrases using dual-cipher encryption (Caesar + Vernam) and splitting them using Shamir's Secret Sharing (SSS).

## ⚠️ CRITICAL SECURITY WARNING ⚠️

**NEVER run this on a connected computer with your real seed phrase.**

**ALWAYS assume there is a keystroke logger and screen recorder running.**

### ⚡ PERSISTENT MALWARE THREAT ⚡

**Modern malware can:**
- Record ALL keystrokes (capturing your seed phrase, offset, OTP)
- Take screenshots/screen recordings (capturing everything you see)
- **STORE this data locally** and wait
- **Upload captured data when you reconnect to the network** - even days/weeks later!

### 🛡️ THE ONLY SAFE APPROACH 🛡️

**Option 1: Dedicated Offline Device (RECOMMENDED)**
1. Obtain a **new Raspberry Pi** or dedicated computer
2. Install Python and required libraries on **another computer** (download packages)
3. Transfer installation files to the Raspberry Pi via USB (offline)
4. Install everything while **NEVER connecting to any network**
5. Run this tool on the air-gapped device
6. **NEVER EVER connect this device to any network** - not now, not later, not ever
7. Store the device securely or destroy it

**Option 2: Device Destruction**
1. Use a Raspberry Pi or cheap computer
2. Install Python and libraries (download offline)
3. Run this tool with your seed phrase
4. **Physically destroy the device** (drill, hammer, fire)
5. NEVER connect it to a network

### ⛔ DO NOT:
- ❌ Run on your daily computer "just this once"
- ❌ Disconnect WiFi temporarily and reconnect later
- ❌ Think "I'll be careful" - malware is invisible
- ❌ Use a virtual machine (host OS may be compromised)
- ❌ Connect the device to network "after formatting" - malware can persist

### Read that warning again. Your financial future depends on it.

This tool handles cryptocurrency wallet seed phrases. Compromised seed phrases mean **permanent and irreversible loss of ALL funds**. There is no recovery, no customer service, no undo button.

---

## 🔒 Security Features

✅ **100% Offline** - Zero network connections, no phone-home functionality
✅ **Cryptographically Secure** - Uses Python's `secrets` module (not `random`)
✅ **Audited SSS Implementation** - Mathematically correct Shamir Secret Sharing
✅ **No External Dependencies** - Only Python standard library + Tkinter
✅ **Air-Gap Safe** - Designed for disconnected operation

### Security Audit Summary

- **Network Activity**: NONE - No socket, urllib, requests, or any network libraries
- **File Operations**: READ-ONLY user-specified files only
- **Random Number Generation**: Cryptographically secure (`secrets` module)
- **Code Execution**: No eval(), exec(), or subprocess calls

---

## 📋 Features

### Encryption
- **Dual-cipher encryption**: Caesar cipher + Vernam cipher (XOR with OTP)
- **Supports 1, 12, or 24-word BIP-39 seed phrases**
- **Customizable offset and One-Time Password (OTP)**
- **Position-specific encryption** with `-i X/Y` flag

### Shamir Secret Sharing (SSS)
- **Split encrypted phrases into N shares** requiring K to reconstruct
- **Embedded mode**: Include offset, OTP, and prime in shares
- **Non-embedded mode**: Manually specify parameters for reconstruction
- **Cryptographically secure** random polynomial coefficients
- **Modular arithmetic** with user-specified or auto-generated prime (>2048)

### User Interface
- **Command-line interface** for scriptable operations
- **Graphical interface (GUI)** for ease of use
- **BIP-39 wordlist viewer** with configurable columns
- **Random word generator** for testing
- **Debug mode** for transparency

---

## 🚀 Installation

### Requirements
- Python 3.7 or higher
- Tkinter (usually included with Python)

### Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/bip39-encryptor.git
cd bip39-encryptor

# No additional dependencies required!
# All libraries are Python standard library
```

### Files
- `encoder.py` - Main application
- `bip39_wordlist.py` - Official BIP-39 English wordlist (2048 words)
- `README.md` - This file

---

## 💻 Usage

### Graphical User Interface (Recommended)

```bash
python3 encoder.py -gui
```

**GUI Features:**

**Random Fill:**
- **Random WORDS** - Fill 1, 12, or 24 random BIP-39 words
- **Random NUMBERS** - Fill 1, 12, or 24 random indices (1-2048)
- Configurable word count field

**Encryption/Decryption:**
- Encrypt seed phrases with Caesar + Vernam ciphers
- Decrypt encrypted phrases
- **VALIDATE** - Round-trip test (encrypt → decrypt → compare)
- **MOVE WORDS UP** - Move encrypted/decrypted words from output to word fields
- Debug mode for transparency

**Parameter Generation:**
- Generate random offset (cryptographically secure)
- Generate random OTP (cryptographically secure)
- Generate random prime (>2048)

**Shamir Secret Sharing:**
- **ENCRYPT SSS** - Create N-of-K shares with embedded or separate parameters
- **DECRYPT SSS** - Paste shares in text area, decrypt with parameters
- Automatic word field population after decryption
- Supports embedded (PRIME:) and non-embedded share formats

**Help & Documentation:**
- **HELP** button - Opens comprehensive help window
- Interactive font adjustment (+/- buttons)
- Complete CLI documentation
- Usage examples and warnings

**User Interface:**
- Scrollable interface (900x800 window)
- 24 word entry fields (supports 1, 12, or 24 words)
- BIP-39 wordlist viewer (10 columns, 2048 words)
- Clear log buttons for output areas
- Confirmation dialogs for destructive operations

### Command-Line Interface

#### Encrypt a seed phrase

```bash
python3 encoder.py -seed "abandon ability able" \
  -offset 1234 \
  -otp "MySecretPassword123" \
  -debug
```

#### Generate random OTP and prime

```bash
python3 encoder.py -seed "abandon ability able" \
  -offset 1234 \
  -otp GENERATE \
  -prime GENERATE
```

#### Encrypt with Shamir Secret Sharing (5-of-3)

```bash
python3 encoder.py -seed "abandon ability able about above absent absorb abstract absurd abuse access accident" \
  -offset 2000 \
  -otp "MySecretOTP1234567890123" \
  -prime 65537 \
  -s 5 3 \
  -embed
```

**Result**: Creates 5 shares, any 3 can reconstruct the secret. Offset, OTP, and prime are embedded in shares.

#### Decrypt a seed phrase

```bash
python3 encoder.py -seed "around arrive ask assault asset" \
  -offset 2000 \
  -otp "MySecretPassword123" \
  -decrypt
```

#### Reconstruct from Shamir shares (embedded parameters)

```bash
python3 encoder.py -sf shares.txt -debug
```

#### Reconstruct from Shamir shares (non-embedded)

```bash
python3 encoder.py -sf shares.txt \
  -offset 2000 \
  -otp "MySecretOTP1234567890123" \
  -prime 65537 \
  -debug
```

#### View BIP-39 wordlist

```bash
python3 encoder.py -bip 4  # Display in 4 columns
```

### Share File Format

Shares must start with `Share X:` where X is the share number. Example:

```
Share 1: PRIME:65537-1,1,123:2,456:3,789
Share 2: PRIME:65537-2,1,234:2,567:3,890
Share 3: PRIME:65537-3,1,345:2,678:3,901
```

Without prime embedded:
```
Share 1: 1-1,123:2,456:3,789
Share 2: 2-1,234:2,567:3,890
```

Lines not starting with `Share X:` are ignored (you can paste raw SSS output).

---

## 🔐 How It Works

### Encryption Process

1. **Caesar Cipher**: Shift BIP-39 word index by offset (modulo 2048)
   ```
   caesar_index = ((original_index - 1) + offset) % 2048 + 1
   ```

2. **Vernam Cipher**: XOR with OTP character's ASCII value (modulo 2048)
   ```
   encrypted_index = (caesar_index ^ ord(otp_char)) % 2048
   ```

3. **Result**: Encrypted BIP-39 word at encrypted_index

### Decryption Process

1. **Reverse Vernam**: XOR with same OTP character
2. **Reverse Caesar**: Subtract offset
3. **Result**: Original BIP-39 word

### Shamir Secret Sharing

- Creates a polynomial of degree `k-1` with random coefficients
- Secret is the constant term (polynomial value at x=0)
- Each share is `(x, P(x) mod prime)` where P is the polynomial
- Any `k` shares can reconstruct the polynomial using Lagrange interpolation
- Uses **cryptographically secure randomness** (`secrets.randbelow()`)

### Position-Specific Encryption (-i X/Y)

Use the same OTP character position for all words:
```bash
python3 encoder.py -seed "annual" \
  -offset 1958 \
  -otp "yyyyyyyyyyyyyyyyyyyyyyyy" \
  -i 23/24
```

This encrypts "annual" using the 23rd character of the OTP, treating it as a 24-word phrase.

---

## 📝 Command-Line Arguments

| Argument | Description |
|----------|-------------|
| `-seed` | BIP-39 seed phrase (1, 12, or 24 words or indices) |
| `-offset` | Caesar cipher offset (non-negative integer) |
| `-otp` | One-Time Password (or `GENERATE` for random) |
| `-prime` | Prime number >2048 for SSS (or `GENERATE` for random) |
| `-s N K` | Create N shares requiring K to reconstruct |
| `-embed` | Embed offset/OTP in SSS shares (requires `-s`) |
| `-sf FILE` | Reconstruct from Shamir shares file |
| `-decrypt` | Decrypt instead of encrypt |
| `-i X/Y` | Use OTP character at position X for Y-word phrase |
| `-bip X` | Print BIP-39 wordlist in X columns |
| `-debug` | Show intermediate cipher values |
| `-gui` | Launch graphical interface |

---

## 🧪 Examples

### Example 1: Encrypt with embedded SSS

```bash
python3 encoder.py \
  -seed "abandon ability able about above absent absorb abstract absurd abuse access accident" \
  -offset 5000 \
  -otp GENERATE \
  -prime GENERATE \
  -s 7 4 \
  -embed
```

**Output**:
- Generated OTP (store securely!)
- 7 shares with PRIME prefix
- Any 4 shares can reconstruct the secret
- No need to remember offset, OTP, or prime (embedded in shares)

### Example 2: GUI Workflow - Complete Encryption & SSS

1. **Launch GUI**: `python3 encoder.py -gui`
2. **Random Fill**: Click **WORDS** button (generates 24 random words)
3. **Generate Parameters**:
   - Click **GENERATE** for Offset
   - Click **GENERATE** for OTP
   - Click **GENERATE** for Prime
4. **Validate**: Click **VALIDATE** button (tests round-trip)
5. **Create Shares**:
   - Enter N=5, K=3 in Shamir section
   - Check **EMBED** checkbox
   - Click **ENCRYPT SSS**
6. **Save Shares**: Copy shares from bottom text area to separate files/locations

### Example 3: GUI Workflow - Decrypt from SSS Shares

1. **Launch GUI**: `python3 encoder.py -gui`
2. **Paste Shares**: In Shamir text area at bottom, paste your shares:
   ```
   Share 1: PRIME:65537-1,1,123:2,456
   Share 2: PRIME:65537-2,1,234:2,567
   Share 3: PRIME:65537-3,1,345:2,678
   ```
3. **Decrypt**: Click **DECRYPT SSS** button (next to ENCRYPT SSS)
4. **Result**: Decrypted words automatically fill the word fields at top
5. **Verify**: Original seed phrase is now recovered!

### Example 4: GUI Workflow - Move Encrypted Words

1. **Fill words** (Random Fill or manual entry)
2. **Set parameters** (Offset, OTP, Prime)
3. Click **ENCRYPT**
4. Click **MOVE WORDS UP** → Confirm
5. Encrypted words now in word fields
6. Click **DECRYPT** to recover original
7. Click **MOVE WORDS UP** again to see recovered words

### Example 5: Simple encryption/decryption

```bash
# Encrypt
python3 encoder.py -seed "abandon" -offset 100 -otp "password123" -i 1/1

# Decrypt (use the output word from encryption)
python3 encoder.py -seed "able" -offset 100 -otp "password123" -i 1/1 -decrypt
```

---

## 🛡️ Best Practices

### 🔴 CRITICAL - Air-Gap Security
1. **Use a Dedicated Device**: Never-connected Raspberry Pi or disposable computer
2. **NEVER Reconnect**: The device must NEVER touch a network - not now, not ever
3. **Physical Security**: Store the device in a safe or destroy it after use
4. **Assume Compromise**: If the device was EVER connected, assume it's compromised

### 🟡 Operational Security
5. **Use Random Generation**: Let the tool generate offset, OTP, and prime (GENERATE buttons in GUI)
6. **Validate First**: Always click **VALIDATE** button in GUI before creating SSS shares
7. **Store Parameters Securely**: Write down offset, OTP, and prime on paper (never digitally)
8. **Use Embedded SSS**: Check **EMBED** checkbox - less chance of losing parameters
9. **Distribute Shares**: Store shares in separate physical locations
10. **Test Recovery**: Practice reconstructing from shares before relying on it (on test device)
11. **Multiple Backups**: Create multiple SSS sets with different parameters

### 🟢 Tool Usage
12. **Verify Everything**: Enable **DEBUG** checkbox to see intermediate values
13. **Use HELP**: Click **HELP** button in GUI for complete documentation
14. **Random Fill for Testing**: Use Random **WORDS** or **NUMBERS** buttons to test functionality
15. **Move Words Carefully**: **MOVE WORDS UP** button has confirmation - read it carefully
16. **Clear Screen After Use**: Prevent shoulder surfing and camera recordings
17. **Destroy Temporary Files**: Securely delete any files created
18. **No Photos**: Never photograph the screen - cameras can be compromised too

---

## 🔬 Testing

### Validate SSS Implementation

```bash
# Encrypt and create shares
python3 encoder.py -seed "abandon" -offset 1000 -otp "test123" -prime 65537 -s 5 3 -embed > shares.txt

# Reconstruct from 3 shares (edit shares.txt to only include 3 shares)
python3 encoder.py -sf shares.txt -debug
```

Expected: Original "abandon" is recovered

### Test GUI Validation Feature

1. Launch GUI: `python3 encoder.py -gui`
2. Click Random Fill **WORDS** button (generates 24 words)
3. Click **GENERATE** for all parameters (Offset, OTP, Prime)
4. Click **VALIDATE** button
5. **Result**: Should show "✓ Round-trip validation passed!"

This tests the complete encrypt → decrypt cycle automatically.

### Test Individual GUI Features

**Random Fill:**
1. Set "# of Words" to 12
2. Click **WORDS** button → 12 random BIP-39 words appear
3. Click **NUMBERS** button → 12 random indices (1-2048) appear

**Move Words Up:**
1. Fill words, encrypt them
2. Click **MOVE WORDS UP** → Confirm
3. Encrypted words move to top fields
4. Click **DECRYPT** → Original words recovered

---

## 🐛 Debugging

Enable debug mode to see intermediate values:

```bash
python3 encoder.py -seed "abandon" -offset 100 -otp "test" -i 1/1 -debug
```

**Output shows**:
- Original word index
- Caesar-shifted index and word
- Vernam XOR result and final encrypted word
- OTP characters used
- Offset and position parameters

---

## 📚 Technical Details

### BIP-39 Specification
- 2048 words in the official English wordlist
- Words are indexed 1-2048 (not 0-2047)
- Source: [BIP-39 GitHub](https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt)

### Cryptographic Primitives
- **Random Generation**: `secrets.randbelow()` - OS entropy source
- **Modular Arithmetic**: All operations mod 2048 or mod prime
- **Extended Euclidean Algorithm**: For modular inverse in SSS

### Algorithm Complexity
- **Encryption**: O(n) where n = number of words
- **SSS Share Generation**: O(n × k) where k = threshold
- **SSS Reconstruction**: O(k²) for Lagrange interpolation

---

## ⚖️ License

This project is released into the public domain. Use at your own risk.

**NO WARRANTY**: This software is provided "as is" without any warranty. The authors are not responsible for any loss of funds or data.

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Test thoroughly (especially cryptographic functions)
4. Submit a pull request

**Security issues**: Please report privately to [your-email@example.com]

---

## 📞 Support

For issues, questions, or suggestions:
- Open a GitHub issue
- Check existing issues first
- Provide full command with `-debug` flag for troubleshooting

---

## 🙏 Acknowledgments

- BIP-39 specification authors
- Adi Shamir for Secret Sharing algorithm
- Python `secrets` module maintainers
- The cryptocurrency community for security best practices

---

## 📖 Further Reading

- [BIP-39 Specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing)
- [Cryptographic Best Practices](https://www.owasp.org/index.php/Cryptographic_Storage_Cheat_Sheet)
- [Air-Gapped Computing](https://en.wikipedia.org/wiki/Air_gap_(networking))

---

**Remember: Your seed phrase security is only as strong as your weakest link. Stay safe!** 🔐
