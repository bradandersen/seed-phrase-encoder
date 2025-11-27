#!/usr/bin/env python3
"""
*****WARNING*****

NEVER run this on a connected computer with your real seed phrase. ALWAYS assume there is a keystroke logger and screen recorder running. Ideally this is run on a disconnected Raspberry Pi after Python and the required libraries are installed.

*****WARNING*****

Now read that last sentence once again

*****WARNING*****

Encrypts or decrypts a BIP-39 seed phrase (1, 12, or 24 words) using a two-phase encryption process:
1. Caesar cipher: Shifts each word's BIP-39 index (1–2048) by a specified offset (modulo 2048).
2. Vernam cipher: XORs the shifted index with the ASCII value of the nth OTP character (1-based), or a specific position with -i X/Y, with modulo 2048 applied to the XOR result.

The OTP must have at least as many characters as the passphrase words (1, 12, or 24); spaces are removed, but case is preserved. Use -otp GENERATE to create a random OTP of the required length (lowercase letters and digits), which is printed for secure storage and used in encryption or SSS embedding. Optionally applies Shamir's Secret Sharing (SSS) to split the encrypted phrase into shares with a random prime (>2048) or reconstructs and decrypts the secret from shares in a file (-sf file.txt) using -offset and -otp. Use -prime to specify a prime for SSS, decryption, or reconstruction; default is -prime GENERATE for a random prime. With -embed, includes offset and OTP in the SSS secret and prefixes shares with PRIME:P-; without -embed, omits PRIME from shares, prints it for secure storage, and requires it for reconstruction. If only -sf is provided, assumes offset and OTP are embedded in the shares. For -sf, handles shares with or without PRIME prefix and ignores lines not starting with 'Share X:'. Supports seed phrase input as BIP-39 words or 1-based indices (1=abandon, 2=ability, ..., 2048=zoo). Prints the BIP-39 wordlist in X columns, numbered 1–2048 down and across, using -bip X. Includes -debug flag to print intermediate Caesar and Vernam cipher values and, with -sf, the raw reconstructed SSS secret. Use -i X/Y to specify the OTP character position X for a Y-word phrase (default: sequential mapping).

Note: To encrypt 'annual' to 'audit' (index 121) with OTP 'yyyyyyyyyyyyyyyyyyyyyyyy' and -i 23/24, use -offset 1958 to produce caesar_index=2048, as (2048 ^ ord('y')=121) % 2048 = 121. The default offset 1972 produces 'august' (index 118).

Usage:
    python encrypt_seed_phrase.py -seed "abandon" -offset 2 -otp "abc" -i 1/1 -prime GENERATE -debug
    python encrypt_seed_phrase.py -seed "abandon" -offset 2 -otp GENERATE -i 1/1 -prime 65537 -debug
    python encrypt_seed_phrase.py -seed "abandon ability ..." -offset 2 -otp "The Quick Brown Fox Jumped Over The Lazy Dog" -i 23/24 -prime 65537 -s 5 3 -embed
    python encrypt_seed_phrase.py -seed "around arrive ..." -offset 2 -otp "MySecretOTP1234567890123" -i 23/24 -prime 65537 -decrypt -debug
    python encrypt_seed_phrase.py -seed "annual" -offset 1958 -otp "yyyyyyyyyyyyyyyyyyyyyyyy" -i 23/24 -debug
    python encrypt_seed_phrase.py -sf shares.txt -offset 2 -otp "MySecretOTP1234567890123" -prime 65537 -debug
    python encrypt_seed_phrase.py -sf shares.txt -debug  # Assumes embedded offset and OTP
    python encrypt_seed_phrase.py -bip 4
    python encrypt_seed_phrase.py -gui  # Run the GUI

File format for -sf file.txt:
    Each line must start with 'Share X: [PRIME:P-]X,Y,...' where P is the prime (optional), X is the share ID,
    and Y,... are x,y pairs separated by colons, with no trailing commas or colons. Example:
        Share 1: PRIME:65537-1,1,123:2,456
        Share 2: 2-1,234:2,567  # No PRIME, requires -prime
        Share 1: 1-1,485884:1,319572:1,80182  # Non-embedded, large share
    Lines not starting with 'Share X:' are ignored. At least k shares are required with consistent format.

Features:
- Supports 1, 12, or 24-word BIP-39 seed phrases (words or 1-based indices).
- Outputs "unencrypted word --> encrypted word" for encryption and "encrypted word --> decrypted word" for decryption.
- Outputs OTP, offset, position (if -i), and prime (if not embedded) used in encryption/decryption, with generated OTP for -otp GENERATE.
- Uses -debug to print intermediate Caesar and Vernam cipher values and raw SSS secret with -sf.
- Uses -embed to include offset and OTP in SSS secret and prefix shares with PRIME:P- (with -s).
- Generates random OTP with -otp GENERATE (lowercase letters and digits) and random prime with -prime GENERATE using cryptographically secure secrets module.
- Allows user-specified prime with -prime for SSS, decryption, or reconstruction.
- Supports -i X/Y for selecting OTP character position X for a Y-word phrase.
- Assumes embedded offset and OTP when only -sf is provided.
- Handles shares with or without PRIME prefix in -sf input, using -prime if needed.
- Ignores non-'Share X:' lines in -sf input to allow reusing SSS output.
- Uses a random prime (>2048) for SSS by default, included in shares or printed.
- Reconstructs and decrypts SSS shares from a file (-sf file.txt) with -offset, -otp, and -prime, or uses embedded values.
- Validates inputs (seed phrase, OTP, offset, prime, position, SSS parameters, BIP columns, shares).
- Imports the full BIP-39 wordlist from bip39_wordlist.py.
- Removes spaces from OTP and preserves case.
- Prints BIP-39 wordlist in X columns with 1-based numbering down and across.
- Custom Shamir's Secret Sharing implementation (no external dependencies).
"""

import argparse
import secrets
import string
from typing import List, Dict, Tuple
from bip39_wordlist import BIP39_WORDS
import sys
import io
from tkinter import Tk, Frame, Label, Entry, Button, Checkbutton, IntVar, messagebox, Toplevel, END, Canvas, Scrollbar, Listbox, SINGLE
from tkinter.scrolledtext import ScrolledText

# Dictionaries for 1-based indexing
WORD_TO_INDEX = {word: idx + 1 for idx, word in enumerate(BIP39_WORDS)}  # 1-based indices
INDEX_TO_WORD = {idx + 1: word for idx, word in enumerate(BIP39_WORDS)}  # 1-based indices

def is_prime(n: int) -> bool:
    """Check if n is prime using trial division (sufficient for small ranges)."""
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for i in range(3, int(n ** 0.5) + 1, 2):
        if n % i == 0:
            return False
    return True

def get_random_prime(min_val: int = 65536, max_val: int = 1000000) -> int:
    """Generate a random prime between min_val and max_val."""
    min_val = max(min_val, 2049)
    candidate = secrets.randbelow(max_val - min_val) // 2 * 2 + min_val + 1
    while not is_prime(candidate):
        candidate += 2
        if candidate > max_val:
            candidate = min_val + 1
    return candidate

def mod_inverse(a: int, m: int) -> int:
    """Compute the modular inverse of a modulo m using extended Euclidean algorithm."""
    def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    gcd, x, _ = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError(f"No modular inverse for {a} modulo {m}")
    return (x % m + m) % m

def generate_shares(secret: int, n: int, k: int, prime: int) -> List[Tuple[int, int]]:
    """Generate n shares for a secret with threshold k using a polynomial modulo prime."""
    if k > n or k < 1 or n < 1:
        raise ValueError("Invalid SSS parameters: k must be <= n and both positive")
    if secret >= prime:
        raise ValueError(f"Secret {secret} must be less than prime {prime}")

    # CRITICAL: Use secrets module for cryptographically secure random coefficients
    coefficients = [secret] + [secrets.randbelow(prime) for _ in range(k - 1)]
    shares = []
    for x in range(1, n + 1):
        y = 0
        for i, coef in enumerate(coefficients):
            y = (y + coef * pow(x, i, prime)) % prime
        shares.append((x, y))
    return shares

def reconstruct_secret(shares: List[Tuple[int, int]], prime: int) -> int:
    """Reconstruct the secret from k shares using Lagrange interpolation modulo prime."""
    if not shares:
        raise ValueError("At least one share is required")
    
    k = len(shares)
    x_values, y_values = zip(*shares)
    if len(set(x_values)) != k:
        raise ValueError("All share x-values must be unique")
    
    secret = 0
    for i in range(k):
        xi, yi = shares[i]
        term = yi
        for j in range(k):
            if i != j:
                xj = shares[j][0]
                numerator = (0 - xj) % prime
                denominator = (xi - xj) % prime
                term = (term * numerator * mod_inverse(denominator, prime)) % prime
        secret = (secret + term) % prime
    return secret

def read_shares_from_file(filename: str, provided_prime: int = None, debug: bool = False) -> Tuple[int, List[Tuple[int, List[Tuple[int, int]]]]]:
    """Read Shamir shares from a text file, extracting the prime or using provided prime."""
    try:
        with open(filename, 'r') as f:
            content = f.read()
        return read_shares_from_string(content, provided_prime, debug)
    except FileNotFoundError:
        raise ValueError(f"Share file {filename} not found")
    except Exception as e:
        raise ValueError(f"Error reading share file: {e}")

def read_shares_from_string(content: str, provided_prime: int = None, debug: bool = False) -> Tuple[int, List[Tuple[int, List[Tuple[int, int]]]]]:
    """Read Shamir shares from a string, extracting the prime or using provided prime."""
    shares = []
    prime = None
    has_prime_prefix = None
    lines = content.splitlines()
    for line in lines:
        line = line.strip()
        if not line or not line.startswith('Share '):
            if debug:
                print(f"Debug: Skipping line: {line}")
            continue
        
        share_content = line[line.find(':') + 1:].strip()
        is_prime_format = share_content.startswith('PRIME:')
        
        if has_prime_prefix is None:
            has_prime_prefix = is_prime_format
        elif has_prime_prefix != is_prime_format:
            raise ValueError("Inconsistent share format: mixed PRIME and non-PRIME shares")
        
        if is_prime_format:
            parts = share_content.split('-', 1)
            if len(parts) != 2:
                raise ValueError(f"Invalid share format: {line}")
            prime_part = parts[0].split(':')[1]
            try:
                current_prime = int(prime_part)
                if current_prime <= 2048:
                    raise ValueError(f"Prime {current_prime} must be greater than 2048")
            except ValueError:
                raise ValueError(f"Invalid prime in share: {prime_part}")
            
            if prime is None:
                prime = current_prime
            elif prime != current_prime:
                raise ValueError(f"Inconsistent primes in shares: {prime} vs {current_prime}")
            share_data = parts[1]
        else:
            if provided_prime is None:
                raise ValueError("Prime must be provided with -prime for shares without PRIME prefix")
            share_data = share_content
            
        try:
            parts = share_data.split('-', 1)
            share_id = int(parts[0])
            points_str = parts[1].strip().rstrip(':')
            if not points_str:
                raise ValueError(f"Empty points in share: {line}")
            points = points_str.split(':')
            share_points = []
            for point in points:
                if not point:
                    raise ValueError(f"Malformed point in share: {line}")
                x, y = map(int, point.split(','))
                if x < 1 or y < 0:
                    raise ValueError(f"Invalid point ({x},{y}) in share: {line}")
                share_points.append((x, y))
            shares.append((share_id, share_points))
            if debug:
                print(f"Debug: Parsed share {share_id} with {len(share_points)} points: {share_points[:5]}{'...' if len(share_points) > 5 else ''}")
        except (ValueError, IndexError):
            raise ValueError(f"Invalid share format: {line}")
    
    if not shares:
        raise ValueError("No valid shares found")
    
    if not has_prime_prefix:
        if provided_prime is None:
            raise ValueError("Prime must be provided with -prime for shares without PRIME prefix")
        if not is_prime(provided_prime) or provided_prime <= 2048:
            raise ValueError(f"Provided prime {provided_prime} must be a prime number greater than 2048")
        prime = provided_prime
    
    if prime is None:
        raise ValueError("No prime found in shares or provided")
    
    if debug:
        print(f"Debug: Using prime {prime}, read {len(shares)} shares with {len(shares[0][1])} points each")
    
    return prime, shares

def print_bip39_wordlist(columns: int) -> None:
    """Print the BIP-39 wordlist in X columns, numbered 1–2048 down and across."""
    if columns < 1:
        raise ValueError("Number of columns must be positive")
    
    total_words = len(BIP39_WORDS)
    rows = (total_words + columns - 1) // columns
    word_list = [(i + 1, word) for i, word in enumerate(BIP39_WORDS)]
    
    table = []
    for row in range(rows):
        table_row = []
        for col in range(columns):
            idx = row + col * rows
            if idx < total_words:
                table_row.append(f"{word_list[idx][0]}.{word_list[idx][1]}")
            else:
                table_row.append("")
        table.append(table_row)
    
    max_width = max(len(cell) for row in table for cell in row) + 2
    for row in table:
        print("".join(cell.ljust(max_width) for cell in row))

def get_words_from_entries(word_entries: list) -> tuple[list[str], tuple[int, int] | None, list[int]]:
    words = []
    filled_indices = []
    for i, e in enumerate(word_entries):
        val = e.get().strip()
        if val:
            if val.isdigit():
                try:
                    idx = int(val)
                    if 1 <= idx <= 2048:
                        word = INDEX_TO_WORD[idx]
                    else:
                        raise ValueError(f"Invalid index {val} for word position {i+1}")
                except ValueError:
                    raise ValueError(f"Invalid number {val} for word position {i+1}")
            elif val in WORD_TO_INDEX:
                word = val
            else:
                raise ValueError(f"Invalid word {val} for word position {i+1}")
            words.append(word)
            filled_indices.append(i + 1)
    num_filled = len(words)
    if num_filled not in (1, 12, 24):
        raise ValueError("Seed phrase must have 1, 12, or 24 words")
    position = None
    if num_filled > 1:
        if sorted(filled_indices) != list(range(1, num_filled + 1)):
            raise ValueError("Words must be entered in consecutive positions starting from Word 1 without gaps.")
    else:
        pos = filled_indices[0]
        position = (pos, 24)
    return words, position, filled_indices

def validate_seed_phrase(seed_phrase: str) -> List[str]:
    """Validate and convert seed phrase (words or 1-based indices) to BIP-39 words."""
    inputs = seed_phrase.strip().split()
    if len(inputs) not in (1, 12, 24):
        raise ValueError("Seed phrase must contain exactly 1, 12, or 24 words or indices")
    
    words = []
    is_numeric = all(input_str.isdigit() for input_str in inputs)
    
    if is_numeric:
        for input_str in inputs:
            idx = int(input_str)
            if idx < 1 or idx > 2048:
                raise ValueError(f"Index {idx} must be between 1 and 2048")
            words.append(INDEX_TO_WORD[idx])
    else:
        if not all(word in WORD_TO_INDEX for word in inputs):
            raise ValueError("All words must be valid BIP-39 words")
        words = inputs
    
    return words

def validate_otp(otp: str, phrase_length: int, position: Tuple[int, int] = None) -> str:
    """Validate the OTP, remove spaces, preserve case, or generate a random OTP."""
    if otp.upper() == "GENERATE":
        characters = string.ascii_lowercase + string.digits
        random_otp = ''.join(secrets.choice(characters) for _ in range(phrase_length))
        print(f"Generated OTP: '{random_otp}' (STORE THIS SECURELY!)")
        return random_otp
    
    cleaned_otp = otp.replace(" ", "")
    if len(cleaned_otp) < phrase_length:
        raise ValueError(f"OTP must have at least {phrase_length} characters (one per passphrase word)")
    if not cleaned_otp.isascii():
        raise ValueError("OTP must contain only ASCII characters")
    
    if position is not None:
        pos, total = position
        if pos < 1 or pos > total or total not in (1, 12, 24):
            raise ValueError(f"Invalid position {pos}/{total}: position must be 1-{total}, total must be 1, 12, or 24")
        if len(cleaned_otp) < pos:
            raise ValueError(f"OTP must have at least {pos} characters for position {pos}/{total}")
    
    return cleaned_otp

def validate_position(position: str) -> Tuple[int, int]:
    """Validate the -i X/Y position argument."""
    try:
        pos, total = map(int, position.split('/'))
        if pos < 1 or pos > total or total not in (1, 12, 24):
            raise ValueError(f"Invalid position {pos}/{total}: position must be 1-{total}, total must be 1, 12, or 24")
        return pos, total
    except ValueError:
        raise ValueError(f"Invalid position format: {position}. Use X/Y where X is position, Y is total (1, 12, or 24)")

def validate_prime(prime: str) -> int:
    """Validate or generate a prime number."""
    if prime.upper() == "GENERATE":
        return get_random_prime()
    
    try:
        prime_val = int(prime)
        if not is_prime(prime_val) or prime_val <= 2048:
            raise ValueError(f"Prime {prime_val} must be a prime number greater than 2048")
        return prime_val
    except ValueError:
        raise ValueError(f"Invalid prime: {prime}. Use a prime number > 2048 or 'GENERATE'.")

def caesar_shift(index: int, offset: int) -> int:
    """Apply Caesar cipher to a 1-based BIP-39 index."""
    return ((index - 1 + offset) % 2048) + 1

def vernam_encrypt(index: int, otp_char: str) -> int:
    """Apply Vernam cipher (XOR) using OTP character ASCII value, with modulo 2048."""
    otp_ascii = ord(otp_char)
    encrypted = (index ^ otp_ascii) % 2048
    return encrypted if encrypted != 0 else 2048

def vernam_decrypt(encrypted_index: int, otp_char: str) -> int:
    """Decrypt Vernam cipher by XORing with the same OTP character, with modulo 2048."""
    otp_ascii = ord(otp_char)
    decrypted = (encrypted_index ^ otp_ascii) % 2048
    return decrypted if decrypted != 0 else 2048

def encrypt_seed_phrase(words: list[str], caesar_offset: int, otp: str, position: Tuple[int, int] = None, debug: bool = False) -> Tuple[List[str], str]:
    """Encrypt a 1, 12, or 24-word seed phrase using Caesar and Vernam ciphers."""
    otp = validate_otp(otp, len(words), position)
    
    encrypted_words = []
    print("Encryption mapping:")
    for i, word in enumerate(words):
        otp_char = otp[position[0] - 1] if position else otp[i]
        index = WORD_TO_INDEX[word]
        caesar_index = caesar_shift(index, caesar_offset)
        caesar_word = INDEX_TO_WORD[caesar_index]
        encrypted_index = vernam_encrypt(caesar_index, otp_char)
        
        if encrypted_index < 1 or encrypted_index > 2048:
            raise ValueError(f"Invalid encrypted index {encrypted_index} for word {word}")
        encrypted_word = INDEX_TO_WORD[encrypted_index]
        encrypted_words.append(encrypted_word)
        
        print(f"{word} --> {encrypted_word}")
        
        if debug:
            print(f"  Debug: Index={index}, Caesar shift({caesar_offset})={caesar_index} ({caesar_word}), "
                  f"Vernam XOR(ord('{otp_char}')={ord(otp_char)})={encrypted_index} ({encrypted_word})")
    
    position_str = f", Position={position[0]}/{position[1]}" if position else ""
    print(f"\nParameters used: OTP='{otp}', Offset={caesar_offset}{position_str}")
    return encrypted_words, otp

def decrypt_seed_phrase(encrypted_phrase: List[str], caesar_offset: int, otp: str, position: Tuple[int, int] = None, debug: bool = False) -> List[str]:
    """Decrypt an encrypted seed phrase."""
    if len(encrypted_phrase) not in (1, 12, 24):
        raise ValueError("Encrypted phrase must contain exactly 1, 12, or 24 words")
    otp = validate_otp(otp, len(encrypted_phrase), position)
    
    decrypted_words = []
    print("Decryption mapping:")
    for i, word in enumerate(encrypted_phrase):
        if word not in WORD_TO_INDEX:
            raise ValueError(f"Invalid BIP-39 word: {word}")
        
        otp_char = otp[position[0] - 1] if position else otp[i]
        encrypted_index = WORD_TO_INDEX[word]
        caesar_index = vernam_decrypt(encrypted_index, otp_char)
        
        if caesar_index < 1 or caesar_index > 2048:
            raise ValueError(f"Invalid caesar index {caesar_index} for word {word}")
        caesar_word = INDEX_TO_WORD[caesar_index]
        index = caesar_shift(caesar_index, -caesar_offset)
        decrypted_word = INDEX_TO_WORD[index]
        decrypted_words.append(decrypted_word)
        
        print(f"{word} --> {decrypted_word}")
        
        if debug:
            print(f"  Debug: Encrypted Index={encrypted_index}, Vernam XOR(ord('{otp_char}')={ord(otp_char)})={caesar_index} ({caesar_word}), "
                  f"Reverse Caesar shift(-{caesar_offset})={index} ({decrypted_word})")
    
    position_str = f", Position={position[0]}/{position[1]}" if position else ""
    print(f"\nParameters used: OTP='{otp}', Offset={caesar_offset}{position_str}")
    return decrypted_words

def apply_shamir_secret_sharing(secret: str, n: int, k: int, embed: bool = False, offset: int = None, otp: str = None, prime: int = None) -> Tuple[List[str], int]:
    """Apply Shamir's Secret Sharing to the secret with a specified or random prime."""
    if prime is None:
        prime = get_random_prime()
    
    if embed:
        if offset is None or otp is None:
            raise ValueError("Offset and OTP must be provided when using -embed")
        secret = f"{secret}|{offset}|{otp}"
        print(f"Encoding into SSS: '{secret}'")
    
    secret_bytes = secret.encode('utf-8')
    secret_int = int.from_bytes(secret_bytes, 'big')
    
    chunk_size = (prime.bit_length() - 1) // 8
    secret_chunks = []
    while secret_int:
        chunk = secret_int % prime
        secret_chunks.append(chunk)
        secret_int //= prime
    
    all_shares = []
    for chunk in secret_chunks:
        shares = generate_shares(chunk, n, k, prime)
        all_shares.append(shares)
    
    share_strings = []
    for i in range(n):
        share_data = [(chunk_shares[i][0], chunk_shares[i][1]) for chunk_shares in all_shares]
        if embed:
            share_str = f"PRIME:{prime}-{i+1}-" + ":".join(f"{x},{y}" for x, y in share_data)
        else:
            share_str = f"{i+1}-" + ":".join(f"{x},{y}" for x, y in share_data)
        share_strings.append(share_str)
    
    if not embed:
        print(f"SSS Prime: {prime} (STORE THIS SECURELY!)")
    
    return share_strings, prime

def reconstruct_shamir_secret(shares: List[Tuple[int, List[Tuple[int, int]]]], prime: int, embed: bool = False, debug: bool = False) -> Tuple[str, int, str]:
    """Reconstruct the secret from Shamir's Secret Sharing shares, optionally extracting embedded offset and OTP."""
    if not shares:
        raise ValueError("No valid shares provided")
    
    num_chunks = len(shares[0][1])
    if not all(len(share[1]) == num_chunks for share in shares):
        raise ValueError(f"Inconsistent number of points across shares: expected {num_chunks}, got {[len(share[1]) for share in shares]}")
    
    max_chunks = 100
    if num_chunks > max_chunks:
        raise ValueError(f"Too many points ({num_chunks}) in shares; maximum allowed is {max_chunks}")
    
    secret_chunks = []
    for chunk_idx in range(num_chunks):
        chunk_shares = [(share[0], share[1][chunk_idx][1]) for share in shares]
        chunk_secret = reconstruct_secret(chunk_shares, prime)
        secret_chunks.append(chunk_secret)
    
    secret_int = 0
    for chunk in reversed(secret_chunks):
        secret_int = secret_int * prime + chunk
    
    try:
        secret_bytes = secret_int.to_bytes((secret_int.bit_length() + 7) // 8, 'big')
        reconstructed_secret = secret_bytes.decode('utf-8')
        
        if debug:
            print(f"Debug: Raw reconstructed SSS secret: '{reconstructed_secret}'")
        
        if embed:
            parts = reconstructed_secret.split('|')
            if len(parts) != 3:
                raise ValueError("Reconstructed secret does not contain valid embedded data (phrase|offset|otp). Perhaps you need to add the -offset and -otp flags as these parameters were not embedded in the Shamir secret.")
            
            phrase = parts[0]
            try:
                offset = int(parts[1])
                if offset < 0:
                    raise ValueError("Embedded offset must be non-negative")
            except ValueError:
                raise ValueError("Invalid embedded offset")
            
            otp = parts[2]
            return phrase, offset, otp
        else:
            return reconstructed_secret, None, None
    except UnicodeDecodeError:
        raise ValueError("Failed to decode reconstructed secret")

class AutocompleteEntry:
    """Provides autocomplete functionality for Entry widgets with BIP-39 wordlist."""

    def __init__(self, entry_widget, wordlist, max_display=10):
        self.entry = entry_widget
        self.wordlist = sorted(wordlist)
        self.max_display = max_display
        self.listbox = None
        self.listbox_visible = False
        self.current_matches = []

        # Bind events
        self.entry.bind('<KeyRelease>', self.on_key_release)
        self.entry.bind('<FocusIn>', self.on_focus_in)
        self.entry.bind('<FocusOut>', self.on_focus_out)
        self.entry.bind('<Down>', self.on_down_arrow)
        self.entry.bind('<Up>', self.on_up_arrow)
        self.entry.bind('<Return>', self.on_return)
        self.entry.bind('<Escape>', self.on_escape)
        self.entry.bind('<Tab>', self.on_tab)

    def on_key_release(self, event):
        """Handle key release events to show/update autocomplete suggestions."""
        # Always update suggestions and validate for any key
        # (except navigation keys that don't change content)
        if event.keysym in ('Up', 'Down', 'Return', 'Escape', 'Tab'):
            # These are handled by their own handlers
            return

        # For all other keys including Delete, BackSpace, and typing - update
        self.update_suggestions()
        self.validate_input()

    def update_suggestions(self):
        """Update the autocomplete suggestions based on current entry text."""
        text = self.entry.get().strip().lower()

        # If empty or is a number, hide suggestions
        if not text or text.isdigit():
            self.hide_listbox()
            self.current_matches = []
            return

        # Filter matching words
        matches = [word for word in self.wordlist if word.startswith(text)]
        self.current_matches = matches

        if matches:
            self.show_suggestions(matches[:self.max_display])
        else:
            self.hide_listbox()

    def validate_input(self):
        """Validate the input and change background color if invalid."""
        text = self.entry.get().strip()

        if not text:
            # Empty field - use default background
            self.entry.config(bg='white')
            return

        # Check if it's a valid index (1-2048)
        if text.isdigit():
            try:
                idx = int(text)
                if 1 <= idx <= 2048:
                    self.entry.config(bg='white')
                else:
                    self.entry.config(bg='#ffcccc')  # Light red
            except ValueError:
                self.entry.config(bg='#ffcccc')  # Light red
            return

        # Check if it's a valid BIP-39 word
        text_lower = text.lower()
        if text_lower in self.wordlist:
            self.entry.config(bg='white')
        else:
            self.entry.config(bg='#ffcccc')  # Light red

    def _calculate_listbox_position(self, num_items):
        """Calculate optimal position for listbox (above or below entry) based on available space."""
        x = self.entry.winfo_x()
        entry_y = self.entry.winfo_y()
        entry_height = self.entry.winfo_height()

        # Estimate listbox height (approximately 20 pixels per item)
        listbox_height = num_items * 20

        # Get the parent frame's height
        parent_height = self.entry.master.winfo_height()

        # Calculate space below and above the entry
        space_below = parent_height - (entry_y + entry_height)
        space_above = entry_y

        # Position below if there's enough space, otherwise position above
        if space_below >= listbox_height or space_below >= space_above:
            # Position below entry
            y = entry_y + entry_height
        else:
            # Position above entry
            y = entry_y - listbox_height

        return x, y

    def show_suggestions(self, matches):
        """Display the autocomplete suggestion listbox, positioned above or below based on available space."""
        num_items = min(len(matches), self.max_display)

        if not self.listbox:
            # Create listbox only if it doesn't exist
            self.listbox = Listbox(self.entry.master, selectmode=SINGLE,
                                  height=num_items,
                                  exportselection=False,
                                  takefocus=1)

            # Position based on available space
            x, y = self._calculate_listbox_position(num_items)
            self.listbox.place(x=x, y=y, width=self.entry.winfo_width())

            # Bind selection and keyboard events
            self.listbox.bind('<<ListboxSelect>>', self.on_listbox_select)
            self.listbox.bind('<Button-1>', self.on_listbox_click)
            self.listbox.bind('<Return>', self.on_listbox_return)
            self.listbox.bind('<Tab>', self.on_listbox_tab)
            self.listbox.bind('<Up>', self.on_listbox_up)
            self.listbox.bind('<Down>', self.on_listbox_down)
            self.listbox.bind('<Escape>', self.on_listbox_escape)
            self.listbox.bind('<KeyPress>', self.on_listbox_keypress)
            self.listbox.bind('<FocusOut>', self.on_listbox_focus_out)
        else:
            # Listbox exists, update height first
            self.listbox.config(height=num_items)

            # Reposition based on available space
            x, y = self._calculate_listbox_position(num_items)
            self.listbox.place(x=x, y=y, width=self.entry.winfo_width())

        # Update listbox contents (fast operation, no flickering)
        self.listbox.delete(0, END)
        for match in matches:
            self.listbox.insert(END, match)

        self.listbox_visible = True
        # Lift to ensure it's visible on top
        self.listbox.lift()

    def hide_listbox(self, event=None):
        """Hide the autocomplete suggestion listbox."""
        if self.listbox:
            try:
                if self.listbox.winfo_ismapped():
                    self.listbox.place_forget()
                self.listbox_visible = False
            except:
                # Listbox was destroyed, reset state
                self.listbox = None
                self.listbox_visible = False

    def on_focus_in(self, event):
        """Handle focus in event - show suggestions if there's text."""
        # When field gets focus, show suggestions for existing text
        text = self.entry.get().strip()
        if text and not text.isdigit():
            self.update_suggestions()

    def on_focus_out(self, event):
        """Handle focus out event - convert number to word, hide listbox unless focus went to listbox."""
        # Convert number to word if applicable
        self.convert_index_to_word()
        # Delay hiding to check where focus went
        self.entry.after(100, self.check_focus_and_hide)

    def check_focus_and_hide(self):
        """Check if listbox has focus, if not hide it."""
        try:
            focused_widget = self.entry.focus_get()
            if focused_widget != self.listbox:
                self.hide_listbox()
        except:
            self.hide_listbox()

    def convert_index_to_word(self):
        """Convert BIP-39 index to word if entry contains a valid number."""
        text = self.entry.get().strip()
        if text.isdigit():
            try:
                idx = int(text)
                if 1 <= idx <= 2048:
                    word = INDEX_TO_WORD[idx]
                    self.entry.delete(0, END)
                    self.entry.insert(0, word)
                    self.entry.config(bg='white')
            except (ValueError, KeyError):
                pass  # Invalid index, leave as is

    def on_down_arrow(self, event):
        """Handle down arrow key to navigate suggestions."""
        if self.listbox_visible and self.listbox:
            # Focus listbox and select first item
            self.listbox.focus_set()
            self.listbox.selection_clear(0, END)
            self.listbox.selection_set(0)
            self.listbox.activate(0)
            self.listbox.see(0)  # Make sure first item is visible
            return 'break'
        return None

    def on_up_arrow(self, event):
        """Handle up arrow key to navigate to last suggestion."""
        if self.listbox_visible and self.listbox:
            # Focus listbox and select last item
            self.listbox.focus_set()
            self.listbox.selection_clear(0, END)
            last_index = self.listbox.size() - 1
            if last_index >= 0:
                self.listbox.selection_set(last_index)
                self.listbox.activate(last_index)
                self.listbox.see(last_index)  # Make sure last item is visible
            return 'break'
        return None

    def on_return(self, event):
        """Handle return key to select highlighted suggestion."""
        if self.listbox_visible and self.listbox:
            selection = self.listbox.curselection()
            if selection:
                self.select_word(self.listbox.get(selection[0]))
                return 'break'

    def on_tab(self, event):
        """Handle tab key to auto-complete and advance to next field."""
        if self.listbox_visible and self.listbox:
            # If listbox is visible, select first item or currently selected item
            selection = self.listbox.curselection()
            if selection:
                self.select_word(self.listbox.get(selection[0]), advance_focus=True)
            elif self.current_matches:
                # Select first match
                self.select_word(self.current_matches[0], advance_focus=True)
            # Don't return 'break' - allow Tab to advance to next widget
            return
        elif self.current_matches and len(self.current_matches) == 1:
            # If only one match exists, auto-fill it
            self.select_word(self.current_matches[0], advance_focus=True)
            # Don't return 'break' - allow Tab to advance to next widget
            return
        else:
            # No matches - convert index to word if applicable
            self.convert_index_to_word()

    def on_escape(self, event):
        """Handle escape key to hide suggestions."""
        if self.listbox_visible:
            self.hide_listbox()
            return 'break'

    def on_listbox_select(self, event):
        """Handle listbox selection."""
        # This is triggered by keyboard navigation
        pass

    def on_listbox_click(self, event):
        """Handle mouse click on listbox item."""
        if self.listbox:
            # Get the clicked item
            index = self.listbox.nearest(event.y)
            if index >= 0:
                word = self.listbox.get(index)
                self.select_word(word)

    def on_listbox_return(self, event):
        """Handle Return key pressed in listbox."""
        if self.listbox:
            selection = self.listbox.curselection()
            if selection:
                word = self.listbox.get(selection[0])
                self.select_word(word)
                return 'break'

    def on_listbox_tab(self, event):
        """Handle Tab key pressed in listbox to select and advance."""
        if self.listbox:
            selection = self.listbox.curselection()
            if selection:
                word = self.listbox.get(selection[0])
                self.select_word(word, advance_focus=True)
            elif self.current_matches:
                # Select first match
                self.select_word(self.current_matches[0], advance_focus=True)
            # Return 'break' to prevent default Tab behavior, we handle focus manually
            return 'break'

    def on_listbox_up(self, event):
        """Handle Up arrow in listbox."""
        if self.listbox:
            current_selection = self.listbox.curselection()
            if current_selection:
                current_index = current_selection[0]
                if current_index == 0:
                    # At top of list, return focus to entry
                    self.entry.focus_set()
                    self.entry.icursor(END)
                    return 'break'
                else:
                    # Move to previous item
                    self.listbox.selection_clear(0, END)
                    self.listbox.selection_set(current_index - 1)
                    self.listbox.activate(current_index - 1)
                    self.listbox.see(current_index - 1)
                    return 'break'

    def on_listbox_down(self, event):
        """Handle Down arrow in listbox."""
        if self.listbox:
            current_selection = self.listbox.curselection()
            if current_selection:
                current_index = current_selection[0]
                # Move to next item if not at end
                if current_index < self.listbox.size() - 1:
                    self.listbox.selection_clear(0, END)
                    self.listbox.selection_set(current_index + 1)
                    self.listbox.activate(current_index + 1)
                    self.listbox.see(current_index + 1)
                    return 'break'

    def on_listbox_escape(self, event):
        """Handle Escape in listbox."""
        self.hide_listbox()
        self.entry.focus_set()
        return 'break'

    def on_listbox_keypress(self, event):
        """Handle typing in listbox - pass back to entry."""
        # If user types a regular character while in listbox, return to entry
        if event.char and event.char.isprintable() and not event.char.isspace():
            self.entry.focus_set()
            # Insert the character at the end of entry
            self.entry.insert(END, event.char)
            return 'break'

    def on_listbox_focus_out(self, event):
        """Handle listbox losing focus."""
        # Delay to check where focus went
        if self.listbox:
            self.listbox.after(100, self.check_listbox_focus_and_hide)

    def check_listbox_focus_and_hide(self):
        """Check if entry has focus, if not hide listbox."""
        try:
            if self.listbox:
                focused_widget = self.listbox.focus_get()
                if focused_widget != self.entry and focused_widget != self.listbox:
                    self.hide_listbox()
        except:
            self.hide_listbox()

    def select_word(self, word, advance_focus=False):
        """Insert the selected word into the entry and hide suggestions."""
        self.entry.delete(0, END)
        self.entry.insert(0, word)
        self.entry.config(bg='white')  # Valid word, set white background
        self.hide_listbox()

        if advance_focus:
            # Return focus to entry so Tab can naturally advance to next widget
            self.entry.focus_set()
            # Generate a Tab event to move to next widget
            self.entry.tk_focusNext().focus_set()
        else:
            # Keep focus on current entry
            self.entry.focus_set()

def run_gui():
    root = Tk()
    root.title("Seed Phrase Encryptor")
    root.geometry("1000x700")

    # Create main frame container
    main_container = Frame(root)
    main_container.pack(fill="both", expand=True)

    # Create canvas and scrollbar
    canvas = Canvas(main_container)
    scrollbar = Scrollbar(main_container, orient="vertical", command=canvas.yview)
    inner_frame = Frame(canvas)

    # Configure scrollbar
    inner_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(
            scrollregion=canvas.bbox("all")
        )
    )

    # Create window in canvas
    canvas.create_window((0, 0), window=inner_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)

    # Pack scrollbar and canvas
    scrollbar.pack(side="right", fill="y")
    canvas.pack(side="left", fill="both", expand=True)

    # Mousewheel scrolling - Mac best practices: use delta directly
    def on_mousewheel(event):
        # Check if we're over a scrollable text widget
        widget_class = event.widget.winfo_class()
        if widget_class == 'Text':
            return

        # Check scroll position FIRST
        yview = canvas.yview()
        at_top = yview[0] <= 0.0
        at_bottom = yview[1] >= 0.9999

        # Use delta directly for smooth Mac scrolling (best practice)
        # Mac sends small delta values (1, -1) which work well with trackpad
        if event.delta > 0:  # Scroll up
            if at_top:
                return "break"
        elif event.delta < 0:  # Scroll down
            if at_bottom:
                return "break"

        # Scroll using negative delta directly for natural direction
        canvas.yview_scroll(-event.delta, "units")

    def on_mousewheel_linux(event):
        widget_class = event.widget.winfo_class()
        if widget_class == 'Text':
            return

        yview = canvas.yview()
        at_top = yview[0] <= 0.0
        at_bottom = yview[1] >= 0.9999

        if event.num == 4:  # Scroll up
            if at_top:
                return "break"
            canvas.yview_scroll(-1, "units")
        elif event.num == 5:  # Scroll down
            if at_bottom:
                return "break"
            canvas.yview_scroll(1, "units")

    # Bind when canvas is entered (best practice pattern)
    def on_canvas_enter(event):
        canvas.bind_all("<MouseWheel>", on_mousewheel)
        canvas.bind_all("<Button-4>", on_mousewheel_linux)
        canvas.bind_all("<Button-5>", on_mousewheel_linux)

    def on_canvas_leave(event):
        canvas.unbind_all("<MouseWheel>")
        canvas.unbind_all("<Button-4>")
        canvas.unbind_all("<Button-5>")

    canvas.bind('<Enter>', on_canvas_enter)
    canvas.bind('<Leave>', on_canvas_leave)

    # Top buttons frame with Random Fill and Show BIP
    top_buttons_frame = Frame(inner_frame)
    top_buttons_frame.pack(pady=10)

    def random_word_fill():
        try:
            num_words = int(num_words_entry.get().strip())
            if num_words not in (1, 12, 24):
                messagebox.showerror("Error", "Number of words must be 1, 12, or 24")
                return
        except:
            messagebox.showerror("Error", "Invalid number of words")
            return

        # Clear all word entries first
        for e in word_entries:
            e.delete(0, END)

        # Fill random words
        random_words = secrets.SystemRandom().sample(BIP39_WORDS, num_words)
        for i, word in enumerate(random_words):
            word_entries[i].insert(0, word)

    def random_number_fill():
        try:
            num_words = int(num_words_entry.get().strip())
            if num_words not in (1, 12, 24):
                messagebox.showerror("Error", "Number of words must be 1, 12, or 24")
                return
        except:
            messagebox.showerror("Error", "Invalid number of words")
            return

        # Clear all word entries first
        for e in word_entries:
            e.delete(0, END)

        # Fill random numbers (1-2048)
        random_numbers = secrets.SystemRandom().sample(range(1, 2049), num_words)
        for i, number in enumerate(random_numbers):
            word_entries[i].insert(0, str(number))

    Label(top_buttons_frame, text="Random Fill:").pack(side="left", padx=5)
    Button(top_buttons_frame, text="WORDS", command=random_word_fill).pack(side="left", padx=2)
    Button(top_buttons_frame, text="NUMBERS", command=random_number_fill).pack(side="left", padx=5)
    Label(top_buttons_frame, text="# of Words:").pack(side="left", padx=5)
    num_words_entry = Entry(top_buttons_frame, width=5)
    num_words_entry.pack(side="left")
    num_words_entry.insert(0, "24")  # Default to 24 words
    Button(top_buttons_frame, text="SHOW BIP-39 WORDS", command=lambda: show_bip()).pack(side="left", padx=5)
    Button(top_buttons_frame, text="HELP", command=lambda: show_help()).pack(side="left", padx=5)

    # Seed words frame
    seed_frame = Frame(inner_frame)
    seed_frame.pack(pady=10)
    Label(seed_frame, text="Seed Phrase Words or BIP-39 indices (e.g. 10 = abuse). Please enter words/indices randomly so keystroke loggers do not obtain your direct pass phrase.").grid(row=0, column=0, columnspan=4)
    word_entries = []
    autocomplete_widgets = []
    # Create entries in vertical order (column by column) so tab moves vertically
    for j in range(2):  # columns
        for i in range(12):  # rows
            idx = j * 12 + i + 1
            if idx > 24:
                break
            Label(seed_frame, text=f"Word {idx}:").grid(row=i+1, column=j*2, sticky="e")
            e = Entry(seed_frame, width=20)
            e.grid(row=i+1, column=j*2+1, sticky="w")
            word_entries.append(e)
            # Add autocomplete to each entry
            autocomplete = AutocompleteEntry(e, BIP39_WORDS)
            autocomplete_widgets.append(autocomplete)
    Button(seed_frame, text="CLEAR ALL", command=lambda: [e.delete(0, END) for e in word_entries]).grid(row=13, column=0, columnspan=4)

    # Parameters frame
    param_frame = Frame(inner_frame)
    param_frame.pack(pady=10)
    Label(param_frame, text="These 2 parameters are critical for decrypting your data, please store them securely. Otherwise, your encrypted information will be lost.").grid(row=0, column=0, columnspan=3)

    Label(param_frame, text="Offset:").grid(row=1, column=0)
    offset_entry = Entry(param_frame)
    offset_entry.grid(row=1, column=1)
    Button(param_frame, text="GENERATE", command=lambda: (offset_entry.delete(0, END), offset_entry.insert(0, str(secrets.randbelow(2048 * 10))))).grid(row=1, column=2)

    Label(param_frame, text="OTP:").grid(row=2, column=0)
    otp_entry = Entry(param_frame, width=50)
    otp_entry.grid(row=2, column=1)
    def gen_otp():
        characters = string.ascii_lowercase + string.digits
        random_otp = ''.join(secrets.choice(characters) for _ in range(24))
        otp_entry.delete(0, END)
        otp_entry.insert(0, random_otp)
    Button(param_frame, text="GENERATE", command=gen_otp).grid(row=2, column=2)

    # Buttons frame
    buttons_frame = Frame(inner_frame)
    buttons_frame.pack(pady=10)

    debug_var = IntVar()
    Checkbutton(buttons_frame, text="DEBUG", variable=debug_var).pack(side="left")

    def on_encrypt():
        try:
            words, position, filled_indices = get_words_from_entries(word_entries)
        except ValueError as e:
            messagebox.showerror("Error", str(e))
            return
        try:
            offset = int(offset_entry.get().strip())
            if offset < 0:
                raise ValueError
        except:
            messagebox.showerror("Error", "Invalid offset")
            return
        otp = otp_entry.get().strip()
        if not otp:
            messagebox.showerror("Error", "OTP required")
            return
        debug = debug_var.get()
        original_stdout = sys.stdout
        out = io.StringIO()
        sys.stdout = out
        try:
            encrypted_words, used_otp = encrypt_seed_phrase(words, offset, otp, position, debug)
            output_text.delete(1.0, END)
            output_text.insert(END, out.getvalue())
            output_text.insert(END, "\nEncrypted seed phrase: " + " ".join(encrypted_words) + "\n")
        except ValueError as e:
            messagebox.showerror("Error", str(e))
        finally:
            sys.stdout = original_stdout

    Button(buttons_frame, text="ENCRYPT", command=on_encrypt).pack(side="left")

    def on_decrypt():
        try:
            words, position, filled_indices = get_words_from_entries(word_entries)
        except ValueError as e:
            messagebox.showerror("Error", str(e))
            return
        try:
            offset = int(offset_entry.get().strip())
            if offset < 0:
                raise ValueError
        except:
            messagebox.showerror("Error", "Invalid offset")
            return
        otp = otp_entry.get().strip()
        if not otp:
            messagebox.showerror("Error", "OTP required")
            return
        debug = debug_var.get()
        original_stdout = sys.stdout
        out = io.StringIO()
        sys.stdout = out
        try:
            decrypted_words = decrypt_seed_phrase(words, offset, otp, position, debug)
            output_text.delete(1.0, END)
            output_text.insert(END, out.getvalue())
            output_text.insert(END, "\nDecrypted seed phrase: " + " ".join(decrypted_words) + "\n")
        except ValueError as e:
            messagebox.showerror("Error", str(e))
        finally:
            sys.stdout = original_stdout

    Button(buttons_frame, text="DECRYPT", command=on_decrypt).pack(side="left")

    def move_words_up():
        # Get text from output
        output_content = output_text.get(1.0, END)

        # Look for "Encrypted seed phrase: " or "Decrypted seed phrase: " line
        # Check both and use the last one found
        found_line = None
        phrase_type = None

        for line in output_content.split('\n'):
            if line.startswith("Encrypted seed phrase:"):
                found_line = line
                phrase_type = "Encrypted"
            elif line.startswith("Decrypted seed phrase:"):
                found_line = line
                phrase_type = "Decrypted"

        if not found_line:
            messagebox.showerror("Error", "No encrypted or decrypted seed phrase found in output. Please encrypt or decrypt first.")
            return

        # Extract words after the prefix
        if phrase_type == "Encrypted":
            prefix = "Encrypted seed phrase: "
        else:
            prefix = "Decrypted seed phrase: "

        words_str = found_line[len(prefix):].strip()
        words = words_str.split()

        if len(words) not in (1, 12, 24):
            messagebox.showerror("Error", f"Invalid number of words: {len(words)}")
            return

        # Ask for confirmation before moving
        confirm = messagebox.askyesno(
            "Confirm Move",
            f"Move {len(words)} {phrase_type.lower()} words to word fields?\n\nThis will clear all existing words.",
            icon='question'
        )

        if not confirm:
            return  # User cancelled

        # Clear all word entries
        for e in word_entries:
            e.delete(0, END)

        # Fill with words
        for i, word in enumerate(words):
            word_entries[i].insert(0, word)

    Button(buttons_frame, text="MOVE WORDS UP", command=move_words_up).pack(side="left", padx=5)

    def validate_encryption():
        # Step 1: Get original words
        try:
            original_words, position, filled_indices = get_words_from_entries(word_entries)
        except ValueError as e:
            messagebox.showerror("Error", str(e))
            return

        # Validate parameters
        try:
            offset = int(offset_entry.get().strip())
            if offset < 0:
                raise ValueError
        except:
            messagebox.showerror("Error", "Invalid offset")
            return

        otp = otp_entry.get().strip()
        if not otp:
            messagebox.showerror("Error", "OTP required")
            return

        debug = debug_var.get()

        # Step 2: Encrypt
        original_stdout = sys.stdout
        out = io.StringIO()
        sys.stdout = out
        try:
            encrypted_words, used_otp = encrypt_seed_phrase(original_words, offset, otp, position, debug)
        except ValueError as e:
            sys.stdout = original_stdout
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
            return
        finally:
            sys.stdout = original_stdout

        # Step 3: Clear and fill with encrypted words
        for e in word_entries:
            e.delete(0, END)
        for i, word in enumerate(encrypted_words):
            word_entries[i].insert(0, word)

        # Step 4: Decrypt
        original_stdout = sys.stdout
        out = io.StringIO()
        sys.stdout = out
        try:
            decrypted_words = decrypt_seed_phrase(encrypted_words, offset, used_otp, position, debug)
            output_text.delete(1.0, END)
            output_text.insert(END, out.getvalue())
        except ValueError as e:
            sys.stdout = original_stdout
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            return
        finally:
            sys.stdout = original_stdout

        # Step 5: Compare original and decrypted words and show detailed results
        # Restore original words to the fields
        for e in word_entries:
            e.delete(0, END)
        for i, word in enumerate(original_words):
            word_entries[i].insert(0, word)

        # Create results window
        results_win = Toplevel()
        results_win.title("Validation Results")
        results_win.geometry("700x500")

        # Header
        header_frame = Frame(results_win)
        header_frame.pack(pady=10)

        if original_words == decrypted_words:
            status_text = "✓ Round-trip validation PASSED!"
            status_color = "green"
        else:
            status_text = "✗ Round-trip validation FAILED!"
            status_color = "red"

        Label(header_frame, text=status_text, font=("Arial", 14, "bold"), fg=status_color).pack()
        Label(header_frame, text=f"Words validated: {len(original_words)}").pack()

        # Results display with table format
        results_text = ScrolledText(results_win, width=90, height=25, font=("Courier", 10))
        results_text.pack(fill="both", expand=True, padx=10, pady=10)

        # Table header
        results_text.insert(END, "Word-by-Word Transformation:\n")
        results_text.insert(END, "=" * 85 + "\n")
        results_text.insert(END, f"{'#':<4} {'Original':<15} {'Encrypted':<15} {'Decrypted':<15} {'Match':<10}\n")
        results_text.insert(END, "-" * 85 + "\n")

        # Table rows
        for i in range(len(original_words)):
            match_status = "✓" if original_words[i] == decrypted_words[i] else "✗ FAIL"
            results_text.insert(END,
                f"{i+1:<4} {original_words[i]:<15} {encrypted_words[i]:<15} {decrypted_words[i]:<15} {match_status:<10}\n")

        results_text.insert(END, "=" * 85 + "\n")
        results_text.insert(END, f"\nParameters used:\n")
        results_text.insert(END, f"  Offset: {offset}\n")
        results_text.insert(END, f"  OTP: {used_otp}\n")
        if position:
            results_text.insert(END, f"  Position: {position[0]}/{position[1]}\n")

        results_text.config(state="disabled")

        # Close button
        Button(results_win, text="CLOSE", command=results_win.destroy, width=15).pack(pady=10)

    Button(buttons_frame, text="VALIDATE", command=validate_encryption).pack(side="left", padx=5)

    # Output text
    output_text = ScrolledText(inner_frame, width=80, height=15)
    output_text.pack(pady=10)
    Button(inner_frame, text="CLEAR LOG", command=lambda: output_text.delete(1.0, END)).pack()

    # Shamir section
    shamir_frame = Frame(inner_frame)
    shamir_frame.pack(pady=10)
    Label(shamir_frame, text="Shamir Secret Sharing:").grid(row=0, column=0, columnspan=6)

    Label(shamir_frame, text="Total Shares (N):").grid(row=1, column=0)
    n_entry = Entry(shamir_frame, width=5)
    n_entry.grid(row=1, column=1)

    Label(shamir_frame, text="Required Shares (K):").grid(row=1, column=2)
    k_entry = Entry(shamir_frame, width=5)
    k_entry.grid(row=1, column=3)

    embed_var = IntVar()
    Checkbutton(shamir_frame, text="EMBED", variable=embed_var).grid(row=1, column=4)

    Label(shamir_frame, text="Prime:").grid(row=2, column=0)
    prime_entry = Entry(shamir_frame, width=20)
    prime_entry.grid(row=2, column=1, columnspan=2)
    Button(shamir_frame, text="GENERATE", command=lambda: (prime_entry.delete(0, END), prime_entry.insert(0, str(get_random_prime())))).grid(row=2, column=3)

    def on_encrypt_sss():
        try:
            words, position, filled_indices = get_words_from_entries(word_entries)
        except ValueError as e:
            messagebox.showerror("Error", str(e))
            return
        try:
            offset = int(offset_entry.get().strip())
            if offset < 0:
                raise ValueError
        except:
            messagebox.showerror("Error", "Invalid offset")
            return
        otp = otp_entry.get().strip()
        if not otp:
            messagebox.showerror("Error", "OTP required")
            return
        try:
            n = int(n_entry.get().strip())
            k = int(k_entry.get().strip())
        except:
            messagebox.showerror("Error", "Invalid N or K")
            return
        embed = embed_var.get()
        prime_input = prime_entry.get().strip() or "GENERATE"
        try:
            prime = validate_prime(prime_input)
        except ValueError as e:
            messagebox.showerror("Error", str(e))
            return
        debug = debug_var.get()
        original_stdout = sys.stdout
        out = io.StringIO()
        sys.stdout = out
        try:
            encrypted_words, used_otp = encrypt_seed_phrase(words, offset, otp, position, debug)
            encrypted_phrase = " ".join(encrypted_words)
            if position and len(encrypted_words) == 1:
                encrypted_phrase = f"pos:{position[0]} {encrypted_words[0]}"
            shares, used_prime = apply_shamir_secret_sharing(encrypted_phrase, n, k, embed, offset, used_otp, prime)
            shamir_text.delete(1.0, END)
            shamir_text.insert(END, out.getvalue())
            shamir_text.insert(END, f"\nShamir's Secret Sharing ({k}-of-{n}):\n")
            for i, share in enumerate(shares, 1):
                shamir_text.insert(END, f"Share {i}: {share}\n")
        except ValueError as e:
            messagebox.showerror("Error", str(e))
        finally:
            sys.stdout = original_stdout

    def on_decrypt_sss():
        content = shamir_text.get(1.0, END).strip()
        if not content:
            messagebox.showerror("Error", "No shares to decrypt. Please paste shares in the Shamir text area below.")
            return

        prime_str = prime_entry.get().strip()
        offset_str = offset_entry.get().strip()
        otp_str = otp_entry.get().strip()

        # Determine if offset and OTP are embedded
        embed_assumed = not offset_str and not otp_str

        provided_prime = None
        if prime_str:
            try:
                provided_prime = int(prime_str)
            except:
                messagebox.showerror("Error", "Invalid prime")
                return

        provided_offset = None
        if offset_str:
            try:
                provided_offset = int(offset_str)
                if provided_offset < 0:
                    raise ValueError
            except:
                messagebox.showerror("Error", "Invalid offset")
                return

        provided_otp = otp_str if otp_str else None
        debug = debug_var.get()

        original_stdout = sys.stdout
        out = io.StringIO()
        sys.stdout = out

        try:
            prime, shares = read_shares_from_string(content, provided_prime, debug)
            reconstructed_secret, reconstructed_offset, reconstructed_otp = reconstruct_shamir_secret(shares, prime, embed=embed_assumed, debug=debug)

            if embed_assumed:
                encrypted_phrase = reconstructed_secret
                offset = reconstructed_offset
                otp = reconstructed_otp
            else:
                encrypted_phrase = reconstructed_secret
                if provided_offset is None:
                    raise ValueError("Offset required if not embedded")
                offset = provided_offset
                if provided_otp is None:
                    raise ValueError("OTP required if not embedded")
                otp = provided_otp

            position = None
            if ' ' in encrypted_phrase and encrypted_phrase.split(' ', 1)[0].startswith('pos:'):
                try:
                    pos_str, rest = encrypted_phrase.split(' ', 1)
                    pos = int(pos_str[4:])
                    if 1 <= pos <= 24:
                        encrypted_words = rest.strip().split()
                        if len(encrypted_words) == 1:
                            position = (pos, 24)
                        else:
                            raise ValueError("Invalid format for single word position")
                    else:
                        raise ValueError("Invalid position")
                except:
                    raise ValueError("Invalid position format in reconstructed secret")
            else:
                encrypted_words = encrypted_phrase.strip().split()

            if len(encrypted_words) not in (1, 12, 24) or not all(word in WORD_TO_INDEX for word in encrypted_words):
                raise ValueError("Reconstructed secret phrase is not a valid BIP-39 seed phrase")

            decrypted_words = decrypt_seed_phrase(encrypted_words, offset, otp, position, debug)

            # Clear word entries
            [e.delete(0, END) for e in word_entries]

            # Fill decrypted words back into main window
            if position and len(decrypted_words) == 1:
                word_entries[position[0] - 1].insert(0, decrypted_words[0])
            else:
                for i, dw in enumerate(decrypted_words):
                    word_entries[i].insert(0, dw)

            # Update offset, OTP, and prime if they were embedded
            if embed_assumed:
                offset_entry.delete(0, END)
                offset_entry.insert(0, str(offset))
                otp_entry.delete(0, END)
                otp_entry.insert(0, otp)
                prime_entry.delete(0, END)
                prime_entry.insert(0, str(prime))

            output_text.delete(1.0, END)
            output_text.insert(END, "Reconstructed encrypted seed phrase: " + encrypted_phrase + "\n")
            output_text.insert(END, out.getvalue())
            output_text.insert(END, "\nDecrypted seed phrase: " + " ".join(decrypted_words) + "\n")

        except Exception as e:
            messagebox.showerror("Error", str(e))
        finally:
            sys.stdout = original_stdout

    Button(shamir_frame, text="ENCRYPT SSS", command=on_encrypt_sss).grid(row=3, column=0, columnspan=2)
    Button(shamir_frame, text="DECRYPT SSS", command=on_decrypt_sss).grid(row=3, column=2, columnspan=3)

    # Shamir output
    shamir_text = ScrolledText(inner_frame, width=80, height=30)
    shamir_text.pack(pady=10)
    Button(inner_frame, text="CLEAR LOG", command=lambda: shamir_text.delete(1.0, END)).pack()

    root.mainloop()

def on_sss_decrypt(root, word_entries, offset_entry, otp_entry, prime_entry, debug_var, output_text):
    decrypt_win = Toplevel(root)
    decrypt_win.title("Decrypt SSS")

    Label(decrypt_win, text="Paste shares here:").pack()
    shares_text = ScrolledText(decrypt_win, width=80, height=40)
    shares_text.pack()

    Label(decrypt_win, text="Prime (if not in shares):").pack()
    prime_dec_entry = Entry(decrypt_win)
    prime_dec_entry.pack()

    Label(decrypt_win, text="Offset (if not embedded):").pack()
    offset_dec_entry = Entry(decrypt_win)
    offset_dec_entry.pack()

    Label(decrypt_win, text="OTP (if not embedded):").pack()
    otp_dec_entry = Entry(decrypt_win, width=50)
    otp_dec_entry.pack()

    debug_dec_var = IntVar(value=debug_var.get())
    Checkbutton(decrypt_win, text="Debug", variable=debug_dec_var).pack()

    def do_decrypt():
        content = shares_text.get(1.0, END).strip()
        prime_str = prime_dec_entry.get().strip()
        provided_prime = int(prime_str) if prime_str else None
        offset_str = offset_dec_entry.get().strip()
        provided_offset = int(offset_str) if offset_str else None
        provided_otp = otp_dec_entry.get().strip() or None
        debug = debug_dec_var.get()
        original_stdout = sys.stdout
        out = io.StringIO()
        sys.stdout = out
        try:
            prime, shares = read_shares_from_string(content, provided_prime, debug)
            embed_assumed = (provided_offset is None and provided_otp is None)
            reconstructed_secret, reconstructed_offset, reconstructed_otp = reconstruct_shamir_secret(shares, prime, embed=embed_assumed, debug=debug)
            if embed_assumed:
                encrypted_phrase = reconstructed_secret
                offset = reconstructed_offset
                otp = reconstructed_otp
            else:
                encrypted_phrase = reconstructed_secret
                if provided_offset is None:
                    raise ValueError("Offset required if not embedded")
                offset = provided_offset
                if provided_otp is None:
                    raise ValueError("OTP required if not embedded")
                otp = provided_otp
            position = None
            if ' ' in encrypted_phrase and encrypted_phrase.split(' ', 1)[0].startswith('pos:'):
                try:
                    pos_str, rest = encrypted_phrase.split(' ', 1)
                    pos = int(pos_str[4:])
                    if 1 <= pos <= 24:
                        encrypted_words = rest.strip().split()
                        if len(encrypted_words) == 1:
                            position = (pos, 24)
                        else:
                            raise ValueError("Invalid format for single word position")
                    else:
                        raise ValueError("Invalid position")
                except:
                    raise ValueError("Invalid position format in reconstructed secret")
            else:
                encrypted_words = encrypted_phrase.strip().split()
            if len(encrypted_words) not in (1, 12, 24) or not all(word in WORD_TO_INDEX for word in encrypted_words):
                raise ValueError("Reconstructed secret phrase is not a valid BIP-39 seed phrase")
            decrypted_words = decrypt_seed_phrase(encrypted_words, offset, otp, position, debug)
            # Clear entries
            [e.delete(0, END) for e in word_entries]
            # Fill back to main
            if position and len(decrypted_words) == 1:
                word_entries[position[0] - 1].insert(0, decrypted_words[0])
            else:
                for i, dw in enumerate(decrypted_words):
                    word_entries[i].insert(0, dw)
            if embed_assumed:
                offset_entry.delete(0, END)
                offset_entry.insert(0, str(offset))
                otp_entry.delete(0, END)
                otp_entry.insert(0, otp)
                prime_entry.delete(0, END)
                prime_entry.insert(0, str(prime))
            output_text.delete(1.0, END)
            output_text.insert(END, "Reconstructed encrypted seed phrase: " + encrypted_phrase + "\n")
            output_text.insert(END, out.getvalue())
            output_text.insert(END, "\nDecrypted seed phrase: " + " ".join(decrypted_words) + "\n")
            decrypt_win.destroy()
        except Exception as e:
            messagebox.showerror("Error", str(e))
        finally:
            sys.stdout = original_stdout

    Button(decrypt_win, text="GO", command=do_decrypt).pack()

def show_bip():
    bip_win = Toplevel()
    bip_win.title("BIP-39 Wordlist")
    bip_win.geometry("1100x700")

    # Font size control
    current_font_size = [12]

    # Buttons at bottom - pack first to ensure visibility
    button_frame = Frame(bip_win)
    button_frame.pack(side="bottom", pady=5)

    # Text area with both scrollbars
    text_frame = Frame(bip_win)
    text_frame.pack(fill="both", expand=True, padx=10, pady=10)

    # Vertical scrollbar
    v_scrollbar = Scrollbar(text_frame)
    v_scrollbar.pack(side="right", fill="y")

    # Horizontal scrollbar
    h_scrollbar = Scrollbar(text_frame, orient="horizontal")
    h_scrollbar.pack(side="bottom", fill="x")

    # Text widget with both scrollbars
    from tkinter import Text
    bip_text = Text(text_frame, width=120, wrap="none",
                    font=("Courier", current_font_size[0]),
                    yscrollcommand=v_scrollbar.set,
                    xscrollcommand=h_scrollbar.set)
    bip_text.pack(fill="both", expand=True)

    v_scrollbar.config(command=bip_text.yview)
    h_scrollbar.config(command=bip_text.xview)

    # Generate wordlist content
    original_stdout = sys.stdout
    out = io.StringIO()
    sys.stdout = out
    print_bip39_wordlist(10)
    sys.stdout = original_stdout
    bip_text.insert(END, out.getvalue())
    bip_text.config(state="disabled")

    # Font size adjustment functions
    def increase_font():
        current_font_size[0] += 2
        bip_text.config(font=("Courier", current_font_size[0]))

    def decrease_font():
        if current_font_size[0] > 6:
            current_font_size[0] -= 2
            bip_text.config(font=("Courier", current_font_size[0]))

    # Add buttons to frame
    Button(button_frame, text="+", command=increase_font, width=3).pack(side="left", padx=2)
    Button(button_frame, text="-", command=decrease_font, width=3).pack(side="left", padx=2)
    Button(button_frame, text="CLOSE", command=bip_win.destroy, width=15).pack(side="left", padx=5)

def get_help_text():
    """Generate the command-line help text."""
    parser = argparse.ArgumentParser(
        description="""

*****WARNING*****

NEVER run this on a connected computer with your real seed phrase. ALWAYS assume there is a keystroke logger and screen recorder running. Ideally this is run on a disconnected Raspberry Pi after Python and the required libraries are installed.

*****WARNING*****

Now read that last sentence once again

*****WARNING*****

Encrypt or decrypt a BIP-39 seed phrase (1, 12, or 24 words) using a Caesar cipher followed by a Vernam cipher.
The Caesar cipher shifts each word's BIP-39 index (1–2048) by an offset (modulo 2048).
The Vernam cipher XORs the shifted index with the ASCII value of the nth OTP character (1-based), or a specific
position with -i X/Y, with modulo 2048 applied to the XOR result. The OTP must have at least as many characters
as the passphrase words (1, 12, or 24); spaces are removed, but case is preserved.
Use -otp GENERATE to create a random OTP (lowercase letters and digits), printed for secure storage and used in
encryption or SSS embedding. Optionally, apply Shamir's Secret Sharing to split the encrypted phrase into shares
with a random prime (>2048) or reconstruct and decrypt the secret from shares in a file (-sf file.txt) using
-offset and -otp. Use -prime to specify a prime for SSS, decryption, or reconstruction; default is -prime GENERATE
for a random prime. With -embed, include offset and OTP in the SSS secret and prefix shares with PRIME:P- (requires
-s); without -embed, omit PRIME from shares, print it for secure storage, and require it for reconstruction.
If only -sf is provided, assumes offset and OTP are embedded in the shares.
For -sf, handles shares with or without PRIME prefix and ignores lines not starting with 'Share X:'.
Input seed phrase as BIP-39 words or 1-based indices (1=abandon, 2=ability, ..., 2048=zoo).
Output shows each word mapping: "unencrypted word --> encrypted word" or "encrypted word --> decrypted word".
Use -bip X to print the BIP-39 wordlist in X columns, numbered 1–2048 down and across.
Use -debug to print intermediate Caesar and Vernam cipher values and raw SSS secret (with -sf) during encryption/decryption.
Use -i X/Y to specify OTP character position X for a Y-word phrase (default: sequential mapping).
"""
    )
    parser.add_argument(
        "-seed",
        help="1, 12, or 24-word BIP-39 seed phrase (space-separated words or 1-based indices). Example: 'abandon' or 'abandon ability ...' or '1 2 3 ...'. Required for encryption/decryption.",
        type=str
    )
    parser.add_argument(
        "-offset",
        help="Caesar cipher offset (non-negative integer). Shifts each word's BIP-39 index. Required for encryption/decryption or -sf unless embedded in shares.",
        type=int
    )
    parser.add_argument(
        "-otp",
        help="""
One-Time Password (ASCII string, at least 1, 12, or 24 characters for 1, 12, or 24-word phrases).
Spaces are removed, case is preserved. Example: 'MySecretOTP123'.
Use 'GENERATE' to create a random OTP (lowercase letters and digits), printed for secure storage.
Required for encryption/decryption or -sf unless embedded in shares.
""",
        type=str
    )
    parser.add_argument(
        "-i",
        help="OTP character position as X/Y (e.g., 23/24 for 23rd char in 24-word phrase). Default: sequential mapping.",
        type=str
    )
    parser.add_argument(
        "-prime",
        help="""
Prime number (>2048) for Shamir's Secret Sharing, decryption, or reconstruction.
Use 'GENERATE' (default) to create a random prime, printed for secure storage if not embedded.
Required for -sf or -decrypt with non-embedded shares. Example: '65537' or 'GENERATE'.
""",
        default="GENERATE",
        type=str
    )
    parser.add_argument(
        "-s", "--shamir",
        nargs=2,
        type=int,
        metavar=('N', 'K'),
        help="""
Apply Shamir's Secret Sharing to the encrypted phrase with a random prime (>2048).
N is the total number of shares, K is the threshold needed to reconstruct.
Example: '-s 5 3' creates 5 shares, requiring 3 to recover.
"""
    )
    parser.add_argument(
        "-sf", "--share-file",
        help="""
Reconstruct and decrypt the secret from Shamir shares in a text file.
Each line must start with 'Share X: [PRIME:P-]X,Y,...' (e.g., 'Share 1: PRIME:65537-1,1,123:2,456' or 'Share 1: 1-1,123:2,456').
Non-'Share X:' lines are ignored. At least k shares are required with consistent format.
Example: '-sf shares.txt'. If -offset and -otp are not provided, assumes they are embedded.
""",
        type=str
    )
    parser.add_argument(
        "-decrypt",
        action="store_true",
        help="Decrypt the input seed phrase instead of encrypting. Use with -seed, -offset, -otp, and -prime if needed."
    )
    parser.add_argument(
        "-bip",
        type=int,
        help="""
Print the BIP-39 wordlist in X columns, numbered 1–2048 down and across.
Example: '-bip 4' prints the wordlist in 4 columns.
"""
    )
    parser.add_argument(
        "-debug",
        action="store_true",
        help="Print intermediate Caesar and Vernam cipher values and raw SSS secret (with -sf) during encryption/decryption."
    )
    parser.add_argument(
        "-embed",
        action="store_true",
        help="Embed the Caesar offset and OTP in the Shamir's Secret Sharing secret and prefix shares with PRIME:P-. Requires -s."
    )
    parser.add_argument(
        "-gui",
        action="store_true",
        help="Run the graphical user interface."
    )
    return parser.format_help()

def show_help():
    help_win = Toplevel()
    help_win.title("Command-Line Help")
    help_win.geometry("900x700")

    # Font size control
    current_font_size = [12]  # Use list to allow modification in nested functions

    # Buttons frame at bottom - pack first to ensure visibility
    button_frame = Frame(help_win)
    button_frame.pack(side="bottom", pady=5)

    # Text area fills remaining space
    help_text = ScrolledText(help_win, width=110, wrap="word", font=("Courier", 12))
    help_text.pack(fill="both", expand=True, padx=10, pady=10)

    # Add the code description from the top of the file
    description = """*****WARNING*****

NEVER run this on a connected computer with your real seed phrase. ALWAYS assume there is a keystroke logger and screen recorder running. Ideally this is run on a disconnected Raspberry Pi after Python and the required libraries are installed.

*****WARNING*****

Now read that last sentence once again

*****WARNING*****

Encrypts or decrypts a BIP-39 seed phrase (1, 12, or 24 words) using a two-phase encryption process:
1. Caesar cipher: Shifts each word's BIP-39 index (1–2048) by a specified offset (modulo 2048).
2. Vernam cipher: XORs the shifted index with the ASCII value of the nth OTP character (1-based), or a specific position with -i X/Y, with modulo 2048 applied to the XOR result.

The OTP must have at least as many characters as the passphrase words (1, 12, or 24); spaces are removed, but case is preserved. Use -otp GENERATE to create a random OTP of the required length (lowercase letters and digits), which is printed for secure storage and used in encryption or SSS embedding. Optionally applies Shamir's Secret Sharing (SSS) to split the encrypted phrase into shares with a random prime (>2048) or reconstructs and decrypts the secret from shares in a file (-sf file.txt) using -offset and -otp. Use -prime to specify a prime for SSS, decryption, or reconstruction; default is -prime GENERATE for a random prime. With -embed, includes offset and OTP in the SSS secret and prefixes shares with PRIME:P-; without -embed, omits PRIME from shares, prints it for secure storage, and requires it for reconstruction. If only -sf is provided, assumes offset and OTP are embedded in the shares. For -sf, handles shares with or without PRIME prefix and ignores lines not starting with 'Share X:'. Supports seed phrase input as BIP-39 words or 1-based indices (1=abandon, 2=ability, ..., 2048=zoo). Prints the BIP-39 wordlist in X columns, numbered 1–2048 down and across, using -bip X. Includes -debug flag to print intermediate Caesar and Vernam cipher values and, with -sf, the raw reconstructed SSS secret. Use -i X/Y to specify the OTP character position X for a Y-word phrase (default: sequential mapping).

Note: To encrypt 'annual' to 'audit' (index 121) with OTP 'yyyyyyyyyyyyyyyyyyyyyyyy' and -i 23/24, use -offset 1958 to produce caesar_index=2048, as (2048 ^ ord('y')=121) % 2048 = 121. The default offset 1972 produces 'august' (index 118).

Usage:
    python encoder.py -seed "abandon" -offset 2 -otp "abc" -i 1/1 -prime GENERATE -debug
    python encoder.py -seed "abandon" -offset 2 -otp GENERATE -i 1/1 -prime 65537 -debug
    python encoder.py -seed "abandon ability ..." -offset 2 -otp "The Quick Brown Fox Jumped Over The Lazy Dog" -i 23/24 -prime 65537 -s 5 3 -embed
    python encoder.py -seed "around arrive ..." -offset 2 -otp "MySecretOTP1234567890123" -i 23/24 -prime 65537 -decrypt -debug
    python encoder.py -seed "annual" -offset 1958 -otp "yyyyyyyyyyyyyyyyyyyyyyyy" -i 23/24 -debug
    python encoder.py -sf shares.txt -offset 2 -otp "MySecretOTP1234567890123" -prime 65537 -debug
    python encoder.py -sf shares.txt -debug  # Assumes embedded offset and OTP
    python encoder.py -bip 4
    python encoder.py -gui  # Run the GUI

File format for -sf file.txt:
    Each line must start with 'Share X: [PRIME:P-]X,Y,...' where P is the prime (optional), X is the share ID,
    and Y,... are x,y pairs separated by colons, with no trailing commas or colons. Example:
        Share 1: PRIME:65537-1,1,123:2,456
        Share 2: 2-1,234:2,567  # No PRIME, requires -prime
        Share 1: 1-1,485884:1,319572:1,80182  # Non-embedded, large share
    Lines not starting with 'Share X:' are ignored. At least k shares are required with consistent format.

Features:
- Supports 1, 12, or 24-word BIP-39 seed phrases (words or 1-based indices).
- Outputs "unencrypted word --> encrypted word" for encryption and "encrypted word --> decrypted word" for decryption.
- Outputs OTP, offset, position (if -i), and prime (if not embedded) used in encryption/decryption, with generated OTP for -otp GENERATE.
- Uses -debug to print intermediate Caesar and Vernam cipher values and raw SSS secret with -sf.
- Uses -embed to include offset and OTP in SSS secret and prefix shares with PRIME:P- (with -s).
- Generates random OTP with -otp GENERATE (lowercase letters and digits) and random prime with -prime GENERATE using cryptographically secure secrets module.
- Allows user-specified prime with -prime for SSS, decryption, or reconstruction.
- Supports -i X/Y for selecting OTP character position X for a Y-word phrase.
- Assumes embedded offset and OTP when only -sf is provided.
- Handles shares with or without PRIME prefix in -sf input, using -prime if needed.
- Ignores non-'Share X:' lines in -sf input to allow reusing SSS output.
- Uses a random prime (>2048) for SSS by default, included in shares or printed.
- Reconstructs and decrypts SSS shares from a file (-sf file.txt) with -offset, -otp, and -prime, or uses embedded values.
- Validates inputs (seed phrase, OTP, offset, prime, position, SSS parameters, BIP columns, shares).
- Imports the full BIP-39 wordlist from bip39_wordlist.py.
- Removes spaces from OTP and preserves case.
- Prints BIP-39 wordlist in X columns with 1-based numbering down and across.
- Custom Shamir's Secret Sharing implementation (no external dependencies).


"""

    help_text.insert(END, description)
    help_text.insert(END, "\n\n" + "="*100 + "\n")
    help_text.insert(END, "COMMAND-LINE ARGUMENTS\n")
    help_text.insert(END, "="*100 + "\n\n")
    help_text.insert(END, get_help_text())
    help_text.config(state="disabled")

    # Font size adjustment functions
    def increase_font():
        current_font_size[0] += 2
        help_text.config(font=("Courier", current_font_size[0]))

    def decrease_font():
        if current_font_size[0] > 6:  # Minimum font size
            current_font_size[0] -= 2
            help_text.config(font=("Courier", current_font_size[0]))

    # Add buttons to the frame (already created above)
    Button(button_frame, text="+", command=increase_font, width=3).pack(side="left", padx=2)
    Button(button_frame, text="-", command=decrease_font, width=3).pack(side="left", padx=2)
    Button(button_frame, text="CLOSE", command=help_win.destroy).pack(side="left", padx=5)

def main():
    parser = argparse.ArgumentParser(
        description="""

*****WARNING*****

NEVER run this on a connected computer with your real seed phrase. ALWAYS assume there is a keystroke logger and screen recorder running. Ideally this is run on a disconnected Raspberry Pi after Python and the required libraries are installed.

*****WARNING*****

Now read that last sentence once again

*****WARNING*****

Encrypt or decrypt a BIP-39 seed phrase (1, 12, or 24 words) using a Caesar cipher followed by a Vernam cipher.
The Caesar cipher shifts each word's BIP-39 index (1–2048) by an offset (modulo 2048).
The Vernam cipher XORs the shifted index with the ASCII value of the nth OTP character (1-based), or a specific
position with -i X/Y, with modulo 2048 applied to the XOR result. The OTP must have at least as many characters
as the passphrase words (1, 12, or 24); spaces are removed, but case is preserved.
Use -otp GENERATE to create a random OTP (lowercase letters and digits), printed for secure storage and used in
encryption or SSS embedding. Optionally, apply Shamir's Secret Sharing to split the encrypted phrase into shares
with a random prime (>2048) or reconstruct and decrypt the secret from shares in a file (-sf file.txt) using
-offset and -otp. Use -prime to specify a prime for SSS, decryption, or reconstruction; default is -prime GENERATE
for a random prime. With -embed, include offset and OTP in the SSS secret and prefix shares with PRIME:P- (requires
-s); without -embed, omit PRIME from shares, print it for secure storage, and require it for reconstruction.
If only -sf is provided, assumes offset and OTP are embedded in the shares.
For -sf, handles shares with or without PRIME prefix and ignores lines not starting with 'Share X:'.
Input seed phrase as BIP-39 words or 1-based indices (1=abandon, 2=ability, ..., 2048=zoo).
Output shows each word mapping: "unencrypted word --> encrypted word" or "encrypted word --> decrypted word".
Use -bip X to print the BIP-39 wordlist in X columns, numbered 1–2048 down and across.
Use -debug to print intermediate Caesar and Vernam cipher values and raw SSS secret (with -sf) during encryption/decryption.
Use -i X/Y to specify OTP character position X for a Y-word phrase (default: sequential mapping).
"""
    )
    parser.add_argument(
        "-seed",
        help="1, 12, or 24-word BIP-39 seed phrase (space-separated words or 1-based indices). Example: 'abandon' or 'abandon ability ...' or '1 2 3 ...'. Required for encryption/decryption.",
        type=str
    )
    parser.add_argument(
        "-offset",
        help="Caesar cipher offset (non-negative integer). Shifts each word's BIP-39 index. Required for encryption/decryption or -sf unless embedded in shares.",
        type=int
    )
    parser.add_argument(
        "-otp",
        help="""
One-Time Password (ASCII string, at least 1, 12, or 24 characters for 1, 12, or 24-word phrases).
Spaces are removed, case is preserved. Example: 'MySecretOTP123'.
Use 'GENERATE' to create a random OTP (lowercase letters and digits), printed for secure storage.
Required for encryption/decryption or -sf unless embedded in shares.
""",
        type=str
    )
    parser.add_argument(
        "-i",
        help="OTP character position as X/Y (e.g., 23/24 for 23rd char in 24-word phrase). Default: sequential mapping.",
        type=str
    )
    parser.add_argument(
        "-prime",
        help="""
Prime number (>2048) for Shamir's Secret Sharing, decryption, or reconstruction.
Use 'GENERATE' (default) to create a random prime, printed for secure storage if not embedded.
Required for -sf or -decrypt with non-embedded shares. Example: '65537' or 'GENERATE'.
""",
        default="GENERATE",
        type=str
    )
    parser.add_argument(
        "-s", "--shamir",
        nargs=2,
        type=int,
        metavar=('N', 'K'),
        help="""
Apply Shamir's Secret Sharing to the encrypted phrase with a random prime (>2048).
N is the total number of shares, K is the threshold needed to reconstruct.
Example: '-s 5 3' creates 5 shares, requiring 3 to recover.
"""
    )
    parser.add_argument(
        "-sf", "--share-file",
        help="""
Reconstruct and decrypt the secret from Shamir shares in a text file.
Each line must start with 'Share X: [PRIME:P-]X,Y,...' (e.g., 'Share 1: PRIME:65537-1,1,123:2,456' or 'Share 1: 1-1,123:2,456').
Non-'Share X:' lines are ignored. At least k shares are required with consistent format.
Example: '-sf shares.txt'. If -offset and -otp are not provided, assumes they are embedded.
""",
        type=str
    )
    parser.add_argument(
        "-decrypt",
        action="store_true",
        help="Decrypt the input seed phrase instead of encrypting. Use with -seed, -offset, -otp, and -prime if needed."
    )
    parser.add_argument(
        "-bip",
        type=int,
        help="""
Print the BIP-39 wordlist in X columns, numbered 1–2048 down and across.
Example: '-bip 4' prints the wordlist in 4 columns.
"""
    )
    parser.add_argument(
        "-debug",
        action="store_true",
        help="Print intermediate Caesar and Vernam cipher values and raw SSS secret (with -sf) during encryption/decryption."
    )
    parser.add_argument(
        "-embed",
        action="store_true",
        help="Embed the Caesar offset and OTP in the Shamir's Secret Sharing secret and prefix shares with PRIME:P-. Requires -s."
    )
    parser.add_argument(
        "-gui",
        action="store_true",
        help="Run the graphical user interface."
    )
    
    args = parser.parse_args()
    
    try:
        if args.gui:
            run_gui()
            return
        
        if args.bip is not None:
            print_bip39_wordlist(args.bip)
            return
        
        if args.embed and not args.shamir:
            raise ValueError("-embed requires -s (Shamir's Secret Sharing)")
        if args.embed and (args.decrypt or args.share_file):
            raise ValueError("-embed cannot be used with -decrypt or -sf")
        
        position = validate_position(args.i) if args.i else None
        
        if args.share_file:
            if args.seed or args.shamir:
                raise ValueError("-sf cannot be used with -seed or -s")
            
            provided_prime = validate_prime(args.prime) if args.prime else None
            prime, shares = read_shares_from_file(args.share_file, provided_prime, args.debug)
            embed_assumed = args.embed or (args.offset is None and args.otp is None)
            
            if not embed_assumed and (args.offset is None or args.offset < 0):
                raise ValueError("Caesar offset is required (-offset) and must be non-negative for -sf unless embedded in shares")
            if not embed_assumed and not args.otp:
                raise ValueError("OTP is required (-otp) for -sf unless embedded in shares")
            
            reconstructed_secret, reconstructed_offset, reconstructed_otp = reconstruct_shamir_secret(shares, prime, embed=embed_assumed, debug=args.debug)
            print("Reconstructed encrypted seed phrase:", reconstructed_secret)
            
            offset = reconstructed_offset if embed_assumed else args.offset
            otp = reconstructed_otp if embed_assumed else args.otp
            
            reconstructed_words = reconstructed_secret.strip().split()
            decrypted_words = decrypt_seed_phrase(reconstructed_words, offset, otp, position, args.debug)
            print("\nDecrypted seed phrase:", " ".join(decrypted_words))
            return
        
        if not args.seed:
            raise ValueError("Seed phrase is required (-seed)")
        if args.offset is None:
            raise ValueError("Caesar offset is required (-offset)")
        if args.offset < 0:
            raise ValueError("Caesar offset must be non-negative")
        if not args.otp:
            raise ValueError("OTP is required (-otp)")
        if args.share_file:
            raise ValueError("-sf cannot be used with -seed")
        
        prime = validate_prime(args.prime)
        
        if args.decrypt:
            encrypted_words = args.seed.strip().split()
            decrypted_words = decrypt_seed_phrase(encrypted_words, args.offset, args.otp, position, args.debug)
            print("\nDecrypted seed phrase:", " ".join(decrypted_words))
        else:
            encrypted_words, used_otp = encrypt_seed_phrase(args.seed, args.offset, args.otp, position, args.debug)
            encrypted_phrase = " ".join(encrypted_words)
            print("\nEncrypted seed phrase:", encrypted_phrase)
            
            if args.shamir:
                n, k = args.shamir
                shares, used_prime = apply_shamir_secret_sharing(encrypted_phrase, n, k, embed=args.embed, offset=args.offset, otp=used_otp, prime=prime)
                print(f"\nShamir's Secret Sharing ({k}-of-{n}):")
                for i, share in enumerate(shares, 1):
                    print(f"Share {i}: {share}")
    
    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()

