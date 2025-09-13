# Challenge 2: Cryptographic Analysis - Multi-Layer Cipher Breaking

## Overview
This challenge tests your ability to analyze and break multiple layers of encryption and encoding techniques commonly found in CTF competitions.

## Challenge Description
You have intercepted an encrypted message that has been processed through multiple cryptographic layers. Your task is to systematically reverse each layer to reveal the hidden flag.

## Files Provided
- `cipher-samples/challenge_data.json` - The encrypted challenge data
- `solution-scripts/crypto_solver.py` - Complete solution script
- `tools/analysis_helpers.py` - Helper tools for analysis

## Challenge Structure

### Layer 4 (Outermost): Number Encoding
- Each character is encoded using: `(ASCII_value * 7) + 13`
- **Decryption**: `(number - 13) / 7 = ASCII_value`

### Layer 3: Substitution Cipher
- Classic substitution cipher with fixed seed (12345)
- Uses pseudo-random alphabet shuffling
- **Attack Method**: Frequency analysis or reverse the algorithm

### Layer 2: Base64 Encoding
- Standard Base64 encoding
- **Decryption**: Use standard Base64 decoder

### Layer 1 (Innermost): Caesar Cipher
- ROT13 (shift = 13)
- **Decryption**: Apply reverse shift of 13

## Quick Start

1. **Analyze the Challenge Data:**
