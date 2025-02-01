Here’s a cleaned-up version of your content:

---

# MoBaCrypt

## Overview
MoBaCrypt is a unique encryption system designed to securely transmit text by combining modified versions of existing ciphers, including a customized AES encryption. This system ensures that data is encrypted with a password, offering enhanced security for sensitive information.

## Description
MoBaCrypt employs a combination of modified AES encryption and classical ciphers to encode and decode text securely. By using password-based encryption, it ensures that only authorized users can access the original message, making it ideal for the secure transmission of sensitive data.

### Encryption Process:
1. **AES Encryption**: If a password is provided, the message is encrypted using a modified AES encryption.
2. **Bacon Cipher**: The text is then transformed using the Bacon Cipher, where each letter is represented by a unique combination of 'A's and 'B's.
3. **Morse Code Mapping**: The Bacon cipher output is further encoded into Morse code, with the option to invert the symbols.
4. **Sequence Selection**: Based on a predefined table, the longest possible Morse code sequence is selected for each letter. This step ensures efficient encoding by maximizing the length of each Morse code sequence.

### Decryption Process:
1. **Text to Morse**: The text is first converted to Morse code.
2. **Bacon Code Mapping**: The Morse code is then mapped to 'A's and 'B's.
3. **Bacon Cipher**: The 'A's and 'B's are converted back into text based on the custom Bacon Cipher table.
4. **AES Decryption**: If a password was provided, it is applied at this stage to decrypt the original message.

This multi-layered approach combines classical and modern encryption techniques, providing a secure and innovative system for protecting sensitive data.