import base64
import string
import math
from collections import Counter

class CryptographyAnalysisTools:
    """Helper tools for cryptographic analysis"""
    
    @staticmethod
    def frequency_analysis(text):
        """Perform frequency analysis on text"""
        freq = {}
        for char in text.upper():
            if char.isalpha():
                freq[char] = freq.get(char, 0) + 1
        total = sum(freq.values())
        
        # Calculate percentages and sort
        freq_percent = {char: (count/total)*100 for char, count in freq.items()}
        return sorted(freq_percent.items(), key=lambda x: x[1], reverse=True)
    
    @staticmethod
    def calculate_entropy(text):
        """Calculate Shannon entropy of text"""
        counter = Counter(text)
        length = len(text)
        entropy = -sum((count/length) * math.log2(count/length) for count in counter.values() if count > 0)
        return entropy
    
    @staticmethod
    def detect_base64(text):
        """Check if text might be Base64 encoded"""
        try:
            # Check character set
            base64_chars = set(string.ascii_letters + string.digits + '+/=')
            if not all(c in base64_chars for c in text):
                return False, "Invalid characters for Base64"
            
            # Check padding
            if len(text) % 4 != 0:
                return False, "Invalid length for Base64"
            
            # Try to decode
            decoded = base64.b64decode(text)
            return True, f"Decoded to: {decoded[:50]}..."
        except Exception as e:
            return False, f"Decoding error: {e}"
    
    @staticmethod
    def caesar_all_shifts(text):
        """Try all possible Caesar cipher shifts"""
        results = {}
        for shift in range(26):
            shifted = ""
            for char in text:
                if char.isalpha():
                    ascii_offset = 65 if char.isupper() else 97
                    shifted_char = chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
                    shifted += shifted_char
                else:
                    shifted += char
            results[shift] = shifted
        return results

def quick_analysis(data):
    """Quick analysis of unknown data"""
    print("🔍 Quick Cryptographic Analysis")
    print("=" * 40)
    
    if isinstance(data, str):
        print(f"Text analysis for: {data[:50]}...")
        print(f"Length: {len(data)}")
        print(f"Entropy: {CryptographyAnalysisTools.calculate_entropy(data):.2f}")
        
        # Check for Base64
        is_b64, b64_result = CryptographyAnalysisTools.detect_base64(data)
        print(f"Base64 check: {is_b64} - {b64_result}")
        
        # Frequency analysis
        freq = CryptographyAnalysisTools.frequency_analysis(data)
        print("Top 5 character frequencies:")
        for char, freq_val in freq[:5]:
            print(f"  {char}: {freq_val:.1f}%")
    
    elif isinstance(data, list) and all(isinstance(x, int) for x in data):
        print(f"Number sequence analysis: {len(data)} numbers")
        print(f"Range: {min(data)} - {max(data)}")
        print(f"Average: {sum(data)/len(data):.1f}")

if __name__ == "__main__":
    print("Cryptographic Analysis Helper Tools")
    print("Use: quick_analysis(your_data)")
