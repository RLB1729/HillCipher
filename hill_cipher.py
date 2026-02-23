# hill_cipher.py
"""
WARNING: For Educational Purposes Only.
This implementation of the Hill cipher is intended strictly for educational 
and experimental use to demonstrate linear algebra concepts in cryptography. 
It is fundamentally vulnerable to known-plaintext attacks and MUST NOT be 
used as a production cryptographic system.
"""

import argparse
import json
import math
import random
import sys
from typing import List

# Standard alphabet used for the cipher
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def char_to_num(c: str, alphabet: str = ALPHABET) -> int:
    """
    Convert a character to its numerical equivalent.

    >>> char_to_num('A')
    0
    >>> char_to_num('Z')
    25
    """
    if alphabet == ALPHABET:
        c = c.upper()
    return alphabet.index(c)

def num_to_char(n: int, alphabet: str = ALPHABET, mod: int = None) -> str:
    """
    Convert a number back to its character equivalent.

    >>> num_to_char(0)
    'A'
    >>> num_to_char(28, mod=26)
    'C'
    """
    if mod is None:
        mod = len(alphabet)
    return alphabet[n % mod]

def get_minor(matrix: List[List[int]], i: int, j: int) -> List[List[int]]:
    """
    Return the minor of the matrix after removing row i and column j.
    Mathematically, this produces the submatrix used to calculate the 
    cofactor: C_{i,j} = (-1)^{i+j} * det(Minor_{i,j}).

    >>> get_minor([[1, 2, 3], [4, 5, 6], [7, 8, 9]], 0, 0)
    [[5, 6], [8, 9]]
    """
    return [row[:j] + row[j+1:] for row in (matrix[:i] + matrix[i+1:])]

def _check_square(mat: List[List[int]]) -> int:
    """Validate that the matrix is square and return its dimension."""
    n = len(mat)
    if any(len(row) != n for row in mat):
        raise ValueError("Matrix must be a square (NxN).")
    return n

def det_mod(mat: List[List[int]], mod: int) -> int:
    """
    Recursively calculate determinant of a square matrix modulo 'mod'.
    
    Mathematical Principle:
    Uses Laplace expansion along the first row:
    det(A) ≡ sum_{j=0}^{n-1} [ (-1)^{0+j} * A_{0,j} * det(Minor_{0,j}) ] (mod m)

    >>> det_mod([[9, 4], [5, 7]], 26)
    17
    """
    n = _check_square(mat)
    if n == 1:
        return mat[0][0] % mod
    if n == 2:
        return (mat[0][0] * mat[1][1] - mat[0][1] * mat[1][0]) % mod

    det = 0
    for c in range(n):
        minor = get_minor(mat, 0, c)
        sign = 1 if c % 2 == 0 else -1
        det += (sign * mat[0][c] * det_mod(minor, mod)) % mod
    return det % mod

def matrix_cofactor(mat: List[List[int]], mod: int) -> List[List[int]]:
    """
    Compute the cofactor matrix modulo 'mod'.
    
    Mathematical Principle:
    Each element C_{i,j} of the cofactor matrix is calculated as:
    C_{i,j} ≡ (-1)^{i+j} * det(Minor_{i,j}) (mod m)

    >>> matrix_cofactor([[9, 4], [5, 7]], 26)
    [[7, 21], [22, 9]]
    """
    n = _check_square(mat)
    if n == 1:
        return [[1 % mod]]

    cofactor_mat = []
    for r in range(n):
        row_cofactors = []
        for c in range(n):
            minor = get_minor(mat, r, c)
            sign = 1 if (r + c) % 2 == 0 else -1
            val = (sign * det_mod(minor, mod)) % mod
            row_cofactors.append(val)
        cofactor_mat.append(row_cofactors)
    return cofactor_mat

def matrix_mod_inv(mat: List[List[int]], mod: int) -> List[List[int]]:
    """
    Calculate the modular inverse of a matrix modulo 'mod'.
    
    Mathematical Principle:
    To invert matrix M modulo m, we multiply the adjugate matrix by the 
    modular multiplicative inverse of the determinant:
    M^{-1} ≡ (det(M)^{-1} * adj(M)) (mod m)
    Where adj(M) is the transpose of the cofactor matrix.

    >>> matrix_mod_inv([[9, 4], [5, 7]], 26)
    [[5, 12], [15, 25]]
    """
    n = _check_square(mat)
    d = det_mod(mat, mod)

    try:
        d_inv = pow(d, -1, mod)
    except ValueError:
        raise ValueError(
            f"Matrix not invertible mod {mod}. "
            f"(Determinant {d} shares a factor with {mod})."
        )

    if n == 1:
        return [[d_inv % mod]]

    cof = matrix_cofactor(mat, mod)
    adjugate = [[cof[c][r] for c in range(n)] for r in range(n)]

    return [[(adjugate[r][c] * d_inv) % mod for c in range(n)] for r in range(n)]

def matrix_mult(A: List[List[int]], B: list, mod: int) -> list:
    """
    Multiply NxM matrix A by MxP matrix B or Mx1 vector B modulo 'mod'.
    Includes dimension validation.
    
    Mathematical Principle:
    Dot product logic mapped over rows and columns, bounded by modulo m.
    Result_{i,j} ≡ sum_{k=0}^{M-1} (A_{i,k} * B_{k,j}) (mod m)

    >>> matrix_mult([[9, 4], [5, 7]], [4, 23], 26)
    [24, 25]
    """
    if not A or not A[0]:
        raise ValueError("Matrix A is empty or invalid.")

    cols_A = len(A[0])
    if any(len(row) != cols_A for row in A):
        raise ValueError("Matrix A has inconsistent row lengths.")
    if not B:
        raise ValueError("Matrix/Vector B is empty.")

    # Vector multiplication
    if isinstance(B[0], int):
        if len(B) != cols_A:
            raise ValueError(f"Dim mismatch: A cols ({cols_A}) != B len ({len(B)}).")
        return [sum(row[i] * B[i] for i in range(cols_A)) % mod for row in A]

    # Matrix multiplication
    rows_B, cols_B = len(B), len(B[0])
    if rows_B != cols_A:
        raise ValueError(f"Dim mismatch: A cols ({cols_A}) != B rows ({rows_B}).")

    result = [[0] * cols_B for _ in range(len(A))]
    for i in range(len(A)):
        for j in range(cols_B):
            result[i][j] = sum(A[i][k] * B[k][j] for k in range(cols_A)) % mod
    return result

def clean_text(text: str, alphabet: str = ALPHABET) -> str:
    """
    Normalize input and remove characters not in the allowed alphabet.

    >>> clean_text("Hello World!")
    'HELLOWORLD'
    """
    if alphabet == ALPHABET:
        text = text.upper()
    return ''.join(c for c in text if c in alphabet)

def encrypt(
    plaintext: str, K: List[List[int]], alphabet: str = ALPHABET, pad_char: str = 'X'
) -> str:
    """
    Encrypt plaintext using the Hill cipher.
    
    Mathematical Principle:
    Splits plaintext into column vectors P of length n.
    C ≡ K * P (mod m)

    >>> encrypt("EXAM", [[9, 4], [5, 7]])
    'YZWG'
    """
    mod, n = len(alphabet), len(K)
    plaintext = clean_text(plaintext, alphabet)

    if len(plaintext) % n != 0:
        if pad_char not in alphabet:
            raise ValueError(f"Pad char '{pad_char}' not in alphabet.")
        while len(plaintext) % n != 0:
            plaintext += pad_char

    ciphertext = ""
    for i in range(0, len(plaintext), n):
        block = plaintext[i : i + n]
        vector = [char_to_num(c, alphabet) for c in block]
        encrypted_vector = matrix_mult(K, vector, mod)
        ciphertext += ''.join(num_to_char(v, alphabet, mod) for v in encrypted_vector)

    return ciphertext

def decrypt(ciphertext: str, K: List[List[int]], alphabet: str = ALPHABET) -> str:
    """
    Decrypt ciphertext using the Hill cipher.
    
    Mathematical Principle:
    Splits ciphertext into column vectors C of length n.
    Computes modular inverse of K.
    P ≡ K^{-1} * C (mod m)

    >>> decrypt("YZWG", [[9, 4], [5, 7]])
    'EXAM'
    """
    mod, n = len(alphabet), len(K)
    ciphertext = clean_text(ciphertext, alphabet)

    if len(ciphertext) % n != 0:
        raise ValueError("Ciphertext length must be a multiple of the key size.")

    inv_K = matrix_mod_inv(K, mod)
    plaintext = ""

    for i in range(0, len(ciphertext), n):
        block = ciphertext[i : i + n]
        vector = [char_to_num(c, alphabet) for c in block]
        decrypted_vector = matrix_mult(inv_K, vector, mod)
        plaintext += ''.join(num_to_char(v, alphabet, mod) for v in decrypted_vector)

    return plaintext

def parse_key(key_str_list: List[str]) -> List[List[int]]:
    """
    Parse a flat list of strings/integers into a square 2D matrix.
    """
    n_squared = len(key_str_list)
    n = int(math.sqrt(n_squared))
    if n * n != n_squared:
        raise ValueError("Key must have a perfect square number of integers.")

    return [[int(x) for x in key_str_list[i * n : (i + 1) * n]] for i in range(n)]

def make_key_from_pass(
    phrase: str, n: int, alphabet: str = ALPHABET, mod: int = None
) -> List[List[int]]:
    """
    Deterministically generate an n x n invertible key matrix from a phrase.
    """
    mod = mod if mod is not None else len(alphabet)
    cleaned = clean_text(phrase, alphabet)

    if not cleaned:
        raise ValueError("Passphrase has no valid alphabet characters.")

    while len(cleaned) < n * n:
        cleaned += cleaned

    cleaned = cleaned[: n * n]
    matrix = [
        [char_to_num(c, alphabet) for c in cleaned[i * n : (i + 1) * n]]
        for i in range(n)
    ]

    det = det_mod(matrix, mod)
    if math.gcd(det, mod) != 1:
        raise ValueError(
            f"Passphrase yields matrix with det {det} (mod {mod}). "
            "This shares a common factor with the modulus. Try again."
        )

    return matrix

def make_random_key(n: int, mod: int) -> List[List[int]]:
    """Generate a random n x n invertible key matrix modulo 'mod'."""
    while True:
        matrix = [[random.randint(0, mod - 1) for _ in range(n)] for _ in range(n)]
        if math.gcd(det_mod(matrix, mod), mod) == 1:
            return matrix

def main():
    parser = argparse.ArgumentParser(description="Educational Hill Cipher Implementation")
    parser.add_argument(
        "--mode", choices=["encrypt", "decrypt"], required=True, help="Mode of operation"
    )
    
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--input", type=str, help="Direct string input")
    input_group.add_argument("--infile", type=str, help="Path to input file")
    
    parser.add_argument("--outfile", type=str, help="Path to output file")
    
    key_group = parser.add_mutually_exclusive_group(required=True)
    key_group.add_argument(
        "--key", nargs="+", help="Space-separated integers for key matrix (e.g. 9 4 5 7)"
    )
    key_group.add_argument(
        "--passphrase", type=str, help="Passphrase to deterministically generate the key"
    )
    key_group.add_argument(
        "--keyfile", type=str, help="Load key matrix from a JSON file"
    )
    key_group.add_argument(
        "--random", action="store_true", help="Generate a random key matrix"
    )
    
    parser.add_argument("--n", type=int, required=True, help="Block size / Matrix dim")
    parser.add_argument("--alphabet", type=str, default=ALPHABET, help="Custom alphabet")
    parser.add_argument(
        "--mod", type=int, default=None, help="Custom modulus (default: len(alphabet))"
    )
    parser.add_argument("--pad", type=str, default="X", help="Padding character")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    mod = args.mod if args.mod is not None else len(args.alphabet)
    
    # 1. Read input
    try:
        if args.infile:
            with open(args.infile, 'r') as f:
                text_input = f.read()
            if args.verbose:
                print(f"[i] Read input from {args.infile}")
        else:
            text_input = args.input
    except IOError as e:
        print(f"File Error: {e}")
        sys.exit(1)
        
    # 2. Get key matrix
    try:
        if args.key:
            key_matrix = parse_key(args.key)
            if len(key_matrix) != args.n:
                raise ValueError(
                    f"Provided key dimension {len(key_matrix)} != --n={args.n}"
                )
            if args.verbose:
                print(f"[i] Parsed Key Matrix: {key_matrix}")
        elif args.passphrase:
            key_matrix = make_key_from_pass(
                args.passphrase, args.n, alphabet=args.alphabet, mod=mod
            )
            if args.verbose:
                print(f"[i] Generated Key Matrix from passphrase: {key_matrix}")
        elif args.random:
            key_matrix = make_random_key(args.n, mod)
            if args.verbose:
                print(f"[i] Generated Random Key Matrix: {key_matrix}")
        elif args.keyfile:
            with open(args.keyfile, 'r') as f:
                key_matrix = json.load(f)
            # Validate it's an NxN matrix
            if len(key_matrix) != args.n or any(len(row) != args.n for row in key_matrix):
                raise ValueError(f"Keyfile matrix dimensions do not match --n={args.n}")
            if args.verbose:
                print(f"[i] Loaded Key Matrix from {args.keyfile}: {key_matrix}")
    except (ValueError, IOError, json.JSONDecodeError) as e:
        print(f"Key Error: {e}")
        sys.exit(1)
        
    # 3. Process
    try:
        if args.mode == "encrypt":
            result = encrypt(
                text_input, key_matrix, alphabet=args.alphabet, pad_char=args.pad
            )
        else:
            result = decrypt(text_input, key_matrix, alphabet=args.alphabet)
            
        if args.verbose:
            print(f"[i] Operation '{args.mode}' completed successfully.")
    except ValueError as e:
        print(f"Cipher Error: {e}")
        sys.exit(1)
        
    # 4. Output
    try:
        if args.outfile:
            with open(args.outfile, 'w') as f:
                f.write(result)
            if args.verbose:
                print(f"[i] Result written to {args.outfile}")
        else:
            # Print directly to stdout
            print(result)
    except IOError as e:
        print(f"File Output Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()