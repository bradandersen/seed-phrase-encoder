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
from tkinter import Tk, Frame, Label, Entry, Button, Checkbutton, IntVar, messagebox, Toplevel, END, Canvas, Scrollbar
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

def run_gui():
    root = Tk()
    root.title("Seed Phrase Encryptor")
    root.geometry("1000x800")

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

    # Mousewheel scrolling support
    def on_mousewheel(event):
        canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        return "break"  # Prevent event propagation

    def on_mousewheel_linux(event):
        if event.num == 4:
            canvas.yview_scroll(-1, "units")
        elif event.num == 5:
            canvas.yview_scroll(1, "units")
        return "break"  # Prevent event propagation

    # Bind mousewheel to the root window so it works everywhere
    root.bind_all("<MouseWheel>", on_mousewheel)
    root.bind_all("<Button-4>", on_mousewheel_linux)
    root.bind_all("<Button-5>", on_mousewheel_linux)

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
    Button(top_buttons_frame, text="SHOW BIP", command=lambda: show_bip()).pack(side="left", padx=5)
    Button(top_buttons_frame, text="HELP", command=lambda: show_help()).pack(side="left", padx=5)

    # Seed words frame
    seed_frame = Frame(inner_frame)
    seed_frame.pack(pady=10)
    Label(seed_frame, text="Seed Phrase Words or BIP-39 indices (e.g. 10 = abuse). Please enter words/indices randomly so keystroke loggers do not obtain your direct pass phrase.").grid(row=0, column=0, columnspan=4)
    word_entries = []
    for i in range(12):
        for j in range(2):
            idx = i * 2 + j + 1
            if idx > 24:
                break
            Label(seed_frame, text=f"Word {idx}:").grid(row=i+1, column=j*2, sticky="e")
            e = Entry(seed_frame, width=20)
            e.grid(row=i+1, column=j*2+1, sticky="w")
            word_entries.append(e)
    Button(seed_frame, text="CLEAR ALL", command=lambda: [e.delete(0, END) for e in word_entries]).grid(row=13, column=0, columnspan=4)

    # Parameters frame
    param_frame = Frame(inner_frame)
    param_frame.pack(pady=10)
    Label(param_frame, text="These 3 parameters are critical for decrypting your data, please store them securely. Otherwise, your encrypted information will be lost.").grid(row=0, column=0, columnspan=3)

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

    Label(param_frame, text="Prime:").grid(row=3, column=0)
    prime_entry = Entry(param_frame)
    prime_entry.grid(row=3, column=1)
    Button(param_frame, text="GENERATE", command=lambda: (prime_entry.delete(0, END), prime_entry.insert(0, str(get_random_prime())))).grid(row=3, column=2)

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

        # Step 5: Compare original and decrypted words
        if original_words == decrypted_words:
            # Restore original words to the fields
            for e in word_entries:
                e.delete(0, END)
            for i, word in enumerate(original_words):
                word_entries[i].insert(0, word)

            messagebox.showinfo(
                "Validation Successful",
                f"✓ Round-trip validation passed!\n\n"
                f"Original words: {len(original_words)}\n"
                f"Encrypted → Decrypted successfully\n"
                f"All words match!"
            )
        else:
            messagebox.showerror(
                "Validation Failed",
                f"✗ Round-trip validation FAILED!\n\n"
                f"Original and decrypted words do not match.\n"
                f"Check your offset and OTP parameters."
            )

    Button(buttons_frame, text="VALIDATE", command=validate_encryption).pack(side="left", padx=5)

    # Output text
    output_text = ScrolledText(inner_frame, width=80, height=15)
    output_text.pack(pady=10)
    Button(inner_frame, text="CLEAR LOG", command=lambda: output_text.delete(1.0, END)).pack()

    # Shamir section
    shamir_frame = Frame(inner_frame)
    shamir_frame.pack(pady=10)
    Label(shamir_frame, text="Shamir Secret Sharing:").grid(row=0, column=0, columnspan=4)

    Label(shamir_frame, text="Total Shares (N):").grid(row=1, column=0)
    n_entry = Entry(shamir_frame, width=5)
    n_entry.grid(row=1, column=1)

    Label(shamir_frame, text="Required Shares (K):").grid(row=1, column=2)
    k_entry = Entry(shamir_frame, width=5)
    k_entry.grid(row=1, column=3)

    embed_var = IntVar()
    Checkbutton(shamir_frame, text="EMBED", variable=embed_var).grid(row=1, column=4)

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

    Button(shamir_frame, text="ENCRYPT SSS", command=on_encrypt_sss).grid(row=2, column=0, columnspan=2)
    Button(shamir_frame, text="DECRYPT SSS", command=on_decrypt_sss).grid(row=2, column=2, columnspan=3)

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
    bip_text = ScrolledText(bip_win, width=160, height=60)
    bip_text.pack(fill="both", expand=True)
    original_stdout = sys.stdout
    out = io.StringIO()
    sys.stdout = out
    print_bip39_wordlist(10)
    sys.stdout = original_stdout
    bip_text.insert(END, out.getvalue())
    bip_text.config(state="disabled")

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

    help_text = ScrolledText(help_win, width=110, height=40, wrap="word", font=("Courier", 12))
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

    # Buttons frame
    button_frame = Frame(help_win)
    button_frame.pack(pady=5)
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

