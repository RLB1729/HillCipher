# tests/test_hill.py
import pytest
import subprocess
import sys
import os

# Add the parent directory to sys.path so we can import hill_cipher modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from hill_cipher import (
    encrypt, decrypt, matrix_mod_inv
)

def test_encryption_decryption_normal():
    """
    Normal case: verify encryption and decryption consistency using a 
    known key matrix and plaintext.
    """
    # Known 2x2 key: [[9, 4], [5, 7]]
    key = [[9, 4], [5, 7]]
    plaintext = "EXAM"
    
    # Encrypt
    ciphertext = encrypt(plaintext, key)
    assert ciphertext == "YZWG"
    
    # Decrypt and verify consistency
    decrypted = decrypt(ciphertext, key)
    assert decrypted == plaintext

def test_non_invertible_matrix_exception():
    """
    Exception case: confirm that non-invertible matrices raise 
    appropriate exceptions in matrix_mod_inv.
    """
    # Matrix with a determinant of 0
    matrix_zero_det = [[2, 4], [1, 2]]
    with pytest.raises(ValueError, match="not invertible"):
        matrix_mod_inv(matrix_zero_det, 26)
        
    # Matrix with a determinant that shares a common factor with mod 26 (det = 2)
    matrix_even_det = [[2, 3], [4, 7]]
    with pytest.raises(ValueError, match="not invertible"):
        matrix_mod_inv(matrix_even_det, 26)

def test_padding_handling():
    """
    Padding test: verify that plaintext requiring padding encrypts 
    and decrypts correctly (with padding properly handled).
    """
    # Key is 2x2, so block size is 2
    key = [[9, 4], [5, 7]]
    
    # "HELLO" is length 5. It will require one pad character ('X') to reach length 6
    plaintext = "HELLO" 
    
    ciphertext = encrypt(plaintext, key, pad_char='X')
    
    # Ensure ciphertext is a multiple of the block size
    assert len(ciphertext) == 6
    
    # Decrypting should return the original text plus the pad character
    decrypted = decrypt(ciphertext, key)
    assert decrypted == "HELLOX"

def test_cli_integration():
    """
    CLI integration test using subprocess to verify the command-line interface.
    """
    script_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'hill_cipher.py'))
    
    # Step 1: Encrypt via CLI
    enc_cmd = [
        sys.executable, script_path, 
        "--mode", "encrypt", 
        "--input", "HELLO", 
        "--passphrase", "TESTINGKEYPHRASE", 
        "--n", "2"
    ]
    
    enc_result = subprocess.run(enc_cmd, capture_output=True, text=True, check=True)
    ciphertext = enc_result.stdout.strip()
    
    # A 5-letter input padded to block size 2 should produce a 6-letter ciphertext
    assert len(ciphertext) == 6
    assert ciphertext.isalpha()
    
    # Step 2: Decrypt via CLI
    dec_cmd = [
        sys.executable, script_path, 
        "--mode", "decrypt", 
        "--input", ciphertext, 
        "--passphrase", "TESTINGKEYPHRASE", 
        "--n", "2"
    ]
    
    dec_result = subprocess.run(dec_cmd, capture_output=True, text=True, check=True)
    decrypted = dec_result.stdout.strip()
    
    # Decrypted text should include the 'X' padding
    assert decrypted == "HELLOX"