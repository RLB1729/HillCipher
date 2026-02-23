Educational Hill Cipher

🚨 WARNING: FOR EDUCATIONAL PURPOSES ONLY

This implementation of the Hill cipher is designed strictly for learning, education, and experimentation.
The Hill cipher is a classical algorithm that relies entirely on linear transformations. It MUST NOT be used to protect sensitive data or used as a production cryptographic system.

Objective

The objective of this project is to provide a pure Python implementation of the Hill cipher without relying on heavy external mathematical libraries (like numpy). By performing all linear algebra and modular arithmetic operations manually, this repository serves as an educational tool for students and developers to clearly understand the underlying mechanics of polygraphic substitution ciphers.

Mathematical Principle

The Hill cipher operates by treating blocks of text as vectors and transforming them using matrix multiplication over modular arithmetic.

Variables:

Let $m$ be the modulus (typically the length of the alphabet, e.g., 26).

Let $\mathbf{P}$ be a column vector representing a block of plaintext of size $n$.

Let $\mathbf{C}$ be a column vector representing a block of ciphertext of size $n$.

Let $\mathbf{K}$ be an $n \times n$ key matrix.

Encryption:
The plaintext vector is multiplied by the key matrix, modulo $m$.

$$\mathbf{C} \equiv \mathbf{K} \cdot \mathbf{P} \pmod{m}$$

Decryption:
The ciphertext vector is multiplied by the inverse of the key matrix, modulo $m$.

$$\mathbf{P} \equiv \mathbf{K}^{-1} \cdot \mathbf{C} \pmod{m}$$

Invertibility Condition (Determinant):
For decryption to be possible, the key matrix $\mathbf{K}$ must be invertible modulo $m$. This requires that the greatest common divisor (GCD) of the matrix's determinant and the modulus is exactly 1:

$$\gcd(\det(\mathbf{K}), m) = 1$$

Modular Inverse of a Matrix:
To compute $\mathbf{K}^{-1}$ algebraically:

$$\mathbf{K}^{-1} \equiv \det(\mathbf{K})^{-1} \cdot \text{adj}(\mathbf{K}) \pmod{m}$$

Where $\det(\mathbf{K})^{-1}$ is the modular multiplicative inverse of the determinant, and $\text{adj}(\mathbf{K})$ is the adjugate matrix (the transpose of the cofactor matrix).

Usage Examples

The script includes a robust CLI tool for performing encryptions and decryptions directly from the terminal.

1. Encrypting with a generated passphrase (Block size $n=3$)

python hill_cipher.py --mode encrypt --input "HELLO" --passphrase "MYPASS" --n 3
# Output: Ciphertext: TFQGE (Note: output will vary based on exact key logic & padding)


2. Decrypting the result

python hill_cipher.py --mode decrypt --input "TFQGE" --passphrase "MYPASS" --n 3
# Output: Plaintext: HELLOX (Includes the 'X' padding applied to reach a multiple of 3)


3. Using raw integers and writing to a file

python hill_cipher.py --mode encrypt --input "SECRET" --key 9 4 5 7 --n 2 --outfile secret.txt


Running Tests

Unit tests are written using pytest and provide complete coverage of the mathematical helper functions, edge cases (such as non-invertible matrices), and the CLI pipeline.

To run the test suite, install pytest and execute:

pip install pytest
pytest tests/test_hill.py


Security Analysis

The Hill cipher is fundamentally broken for modern use due to its purely linear mathematical structure.

The Attack Surface (Linearity): The core vulnerability of the Hill cipher is that matrix multiplication is a linear operation. It lacks confusion and non-linear diffusion, meaning patterns in the plaintext can map predictably to the ciphertext if the mathematical structure is exposed.

Key Recovery via Known-Plaintext Attack: Because encryption relies purely on $\mathbf{C} = \mathbf{K} \cdot \mathbf{P}$, an attacker who intercepts a known plaintext and its corresponding ciphertext can easily recover the key. By gathering $n$ linearly independent plaintext vectors and their ciphertext vector counterparts, the attacker can form two $n \times n$ matrices: $\mathbf{P_{mat}}$ and $\mathbf{C_{mat}}$. Since $\mathbf{C_{mat}} \equiv \mathbf{K} \cdot \mathbf{P_{mat}} \pmod{m}$, the attacker simply computes $\mathbf{K} \equiv \mathbf{C_{mat}} \cdot \mathbf{P_{mat}}^{-1} \pmod{m}$. This instantly reveals the exact key matrix $\mathbf{K}$ using standard linear algebra, entirely bypassing the need to brute-force the key space.

Suggested Improvements

To experiment with hardening this cipher (while remaining in the educational realm), consider implementing the following enhancements to break its linearity:

Random IV with CBC-Style Feedback: Instead of standard Electronic Codebook (ECB) mode, implement Cipher Block Chaining (CBC). Generate a random Initialization Vector (IV) for the first block, and XOR the current plaintext vector with the previous ciphertext vector before applying the matrix transformation. This provides semantic security and diffuses patterns.

Rotating Keys: Dynamically alter the key matrix $\mathbf{K}$ for each block (e.g., using a deterministic key schedule or derivation function) rather than using a static key matrix for the entire message.

Non-Linear Stream XOR (LFSR): Break the linearity entirely by combining the Hill cipher's output with a non-linear component. For example, XOR the resulting Hill matrix against a pseudo-random stream generated by a Linear Feedback Shift Register (LFSR).

Performance Considerations

When experimenting with this implementation, keep the mathematical complexity of matrix operations in mind:

Matrix Operations Complexity: Standard matrix multiplication has a time complexity of $O(n^3)$. More severely, computing the determinant and the adjugate matrix using recursive Laplace expansion (as done in this pure Python implementation) has a time complexity approaching $O(n!)$.

Recommended Block Sizes: It is highly recommended to stick to practical block sizes of $n = 2$ to $n = 4$.

Justification: Increasing the block size $n$ does not effectively secure the cipher against known-plaintext attacks (since solving a system of linear equations is still trivial for computers at slightly larger sizes). However, large block sizes will exponentially degrade performance and cause massive computational overhead during the key inversion step without providing any meaningful cryptographic benefit.