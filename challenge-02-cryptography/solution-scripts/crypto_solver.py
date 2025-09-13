import base64
import string
import random
import json

class CryptoSolver:
    def __init__(self):
        # Create reverse substitution key
        self.sub_key_reverse = self.create_reverse_substitution()
    
    def create_reverse_substitution(self):
        """Create reverse substitution key"""
        alphabet = list(string.ascii_uppercase)
        shuffled = alphabet.copy()
        random.seed(12345)  # Same seed as used in challenge
        random.shuffle(shuffled)
        
        # Create reverse mapping
        forward_key = dict(zip(alphabet, shuffled))
        return {v: k for k, v in forward_key.items()}
    
    def reverse_number_encoding(self, numbers):
        """Reverse the number encoding: (ASCII * 7) + 13"""
        result = ""
        for num in numbers:
            # Reverse: (num - 13) / 7 = ASCII
            ascii_val = (num - 13) // 7
            result += chr(ascii_val)
        return result
    
    def reverse_substitution(self, text):
        """Reverse the substitution cipher"""
        result = ""
        for char in text:
            if char.upper() in self.sub_key_reverse:
                result += self.sub_key_reverse[char.upper()] if char.isupper() else self.sub_key_reverse[char.upper()].lower()
            else:
                result += char
        return result
    
    def caesar_decrypt(self, text, shift):
        """Decrypt Caesar cipher"""
        return self.caesar_cipher(text, -shift)
    
    def caesar_cipher(self, text, shift):
        """Caesar cipher implementation"""
        result = ""
        for char in text:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                shifted = (ord(char) - ascii_offset + shift) % 26
                result += chr(shifted + ascii_offset)
            else:
                result += char
        return result
    
    def solve_challenge(self, challenge_file):
        """Solve the complete challenge"""
        print("🔓 Solving Multi-Layer Cryptographic Challenge...")
        
        # Load challenge data
        with open(challenge_file, 'r') as f:
            data = json.load(f)
        
        encrypted_numbers = data['encrypted_data']
        print(f"Step 0: Loaded encrypted data: {encrypted_numbers[:10]}... (showing first 10)")
        
        # Step 1: Reverse number encoding
        print("\nStep 1: Reversing Number Encoding...")
        layer3_text = self.reverse_number_encoding(encrypted_numbers)
        print(f"After number decoding: {layer3_text}")
        
        # Step 2: Reverse substitution cipher
        print("\nStep 2: Substitution Cipher Reversal...")
        layer2_text = self.reverse_substitution(layer3_text)
        print(f"After substitution reversal: {layer2_text}")
        
        # Step 3: Base64 decoding
        print("\nStep 3: Base64 Decoding...")
        try:
            layer1_text = base64.b64decode(layer2_text).decode()
            print(f"After Base64 decoding: {layer1_text}")
        except Exception as e:
            print(f"Base64 decoding failed: {e}")
            return None
        
        # Step 4: Caesar cipher decryption (ROT13)
        print("\nStep 4: Caesar Cipher Decryption (ROT13)...")
        final_flag = self.caesar_decrypt(layer1_text, 13)
        print(f"🎉 FINAL FLAG: {final_flag}")
        
        return final_flag

    def brute_force_caesar(self, text):
        """Try all possible Caesar shifts"""
        print("Brute forcing Caesar cipher...")
        for shift in range(26):
            decrypted = self.caesar_cipher(text, shift)
            print(f"Shift {shift:2}: {decrypted}")

if __name__ == "__main__":
    solver = CryptoSolver()
    
    # Example usage
    print("Multi-Layer Cryptographic Challenge Solver")
    print("==========================================")
    print()
    
    # Solve the challenge
    try:
        result = solver.solve_challenge('../cipher-samples/challenge_data.json')
        if result:
            print(f"\n✅ Challenge solved! Flag: {result}")
        else:
            print("\n❌ Challenge solving failed!")
    except FileNotFoundError:
        print("Challenge data file not found. Make sure you're in the solution-scripts directory.")
    except Exception as e:
        print(f"Error: {e}")
