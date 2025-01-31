async function encryptDecryptMessage(action, layer, tb1offset, tb2offset, inver, message, password) {
    let finalResult = message; // Initialize finalResult with the initial message

    // Morse Code Map
    const morseCodeMap = {
        '.-': 'A',     '-...': 'B',   '-.-.': 'C',   '-..': 'D',    '.': 'E',     
        '..-.': 'F',   '--.': 'G',    '....': 'H',   '..': 'I',     '.---': 'J',  
        '-.-': 'K',    '.-..': 'L',   '--': 'M',     '-.': 'N',     '---': 'O',   
        '.--.': 'P',   '--.-': 'Q',   '.-.': 'R',    '...': 'S',    '-': 'T',     
        '..-': 'U',    '...-': 'V',   '.--': 'W',    '-..-': 'X',   '-.--': 'Y',  
        '--..': 'Z',   
        '.----': '1',  '..---': '2',  '...--': '3',  '....-': '4',   '.....': '5',  
        '-....': '6',  '--...': '7',   '---..': '8',  '----.': '9',   '-----': '0', 
        '.-.-.-': '.', '--..--': ',', '..--..': '?', '.----.': "'",   '-.-.--': '!', 
        '-..-.': '/',  '-.--.': '(',   '-.--.-': ')', '.-...': '&',    '---...': ':', 
        '-.-.-.': ';', '-...-': '=',   '.-.-.': '+',   '-....-': '-',   '..--.-': '_', 
        '.-..-.': '"', '...-..-': '$',  '.--.-.': '@',  ' ': ' '
    };

    // Bacon Cipher Key
    const baconCipherKey = {
        'A': 'AAAAAAA', 'B': 'AAAAAAB', 'C': 'AAAAABA', 'D': 'AAAAABB', 'E': 'AAAABAA', 
        'F': 'AAAABAB', 'G': 'AAAABBA', 'H': 'AAAABBB', 'I': 'AAABAAA', 'J': 'AAABAAB', 
        'K': 'AAABABA', 'L': 'AAABABB', 'M': 'AAABBAA', 'N': 'AAABBAB', 'O': 'AAABBBA', 
        'P': 'AAABBBB', 'Q': 'AABAAAA', 'R': 'AABAAAB', 'S': 'AABAABA', 'T': 'AABAABB', 
        'U': 'AABABAA', 'V': 'AABABAB', 'W': 'AABABBA', 'X': 'AABABBB', 'Y': 'AABBAAA', 
        'Z': 'AABBAAB', '0': 'AABBABA', '1': 'AABBABB', '2': 'AABBBAA', '3': 'AABBBAB', 
        '4': 'AABBBBA', '5': 'AABBBBB', '6': 'ABAAAAA', '7': 'ABAAAAB', '8': 'ABAAABA', 
        '9': 'ABAAABB', '~': 'ABAABAA', '!': 'ABAABAB', '@': 'ABAABBA', '#': 'ABAABBB',
        '$': 'ABABAAA', '%': 'ABABAAB', '^': 'ABABABA', '&': 'ABABABB', '*': 'ABABBAA', 
        '(': 'ABABBAB', ')': 'ABABBBA', '-': 'ABABBBB', '_': 'ABBAAAA', '=': 'ABBAAAB', 
        '+': 'ABBAABA', '[': 'ABBAABB', ']': 'ABBABAA', '{': 'ABBABAB', '}': 'ABBABBA', 
        '\\': 'ABBABBB', '|': 'ABBBAAA', ';': 'ABBBAAB', ':': 'ABBBABA', '\'': 'ABBBABB', 
        '"': 'ABBBBAA', ',': 'ABBBBAB', '<': 'ABBBBBA', '.': 'ABBBBBB', '>': 'BAAAAAA', 
        '/': 'BAAAAAB', '?': 'BAAAABA', '`': 'BAAAABB', ' ': 'BAAABAA', 
        'a': 'BAAABAB', 'b': 'BAAABBA', 'c': 'BAAABBB', 'd': 'BAABAAA', 'e': 'BAABAAB', 
        'f': 'BAABABA', 'g': 'BAABABB', 'h': 'BAABBAA', 'i': 'BAABBAB', 'j': 'BAABBBA', 
        'k': 'BAABBBB', 'l': 'BABAAAA', 'm': 'BABAAAB', 'n': 'BABAABA', 'o': 'BABAABB', 
        'p': 'BABABAA', 'q': 'BABABAB', 'r': 'BABABBA', 's': 'BABABBB', 't': 'BABBAAA', 
        'u': 'BABBAAB', 'v': 'BABBABA', 'w': 'BABBABB', 'x': 'BABBBAA', 'y': 'BABBBAB', 
        'z': 'BABBBBA'
    };

    // Function to apply offset to a given table
    function applyOffset(table, offset) {
        const keys = Object.keys(table);
        const values = Object.values(table);
        const newTable = {};
        
        for (let i = 0; i < keys.length; i++) {
            const newIndex = (i + offset) % keys.length; // Wrap around using modulo
            newTable[keys[newIndex]] = values[i];
        }
        return newTable;
    }

    // Apply offsets to Morse and Bacon tables
    const morseCodeMapWithOffset = applyOffset(morseCodeMap, tb1offset);
    const baconCipherKeyWithOffset = applyOffset(baconCipherKey, tb2offset);

    function stringToArrayBuffer(str) {
        const encoder = new TextEncoder();
        return encoder.encode(str);
    }
    function arrayBufferToString(buffer) {
        const decoder = new TextDecoder();
        return decoder.decode(buffer);
    }
    async function hashPassword(password) {
        const encoder = new TextEncoder();
        const passwordBuffer = encoder.encode(password);
        const hashBuffer = await crypto.subtle.digest('SHA-256', passwordBuffer);
        return new Uint8Array(hashBuffer);
    }
    async function deriveKey(passwordHash, salt) {
        const saltBuffer = stringToArrayBuffer(salt);
        const keyMaterial = await crypto.subtle.importKey(
            "raw", 
            passwordHash, 
            { name: "PBKDF2" }, 
            false, 
            ["deriveKey"]
        );
        
        return await crypto.subtle.deriveKey(
            { name: "PBKDF2", salt: saltBuffer, iterations: 100000, hash: "SHA-256" },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"]
        );
    }

    for (let i = 0; i < layer; i++) {
        if (action === "encode") {
            if (password !== undefined && password !== "") {
                const salt = crypto.getRandomValues(new Uint8Array(16)); // 16 bytes salt
                const iv = crypto.getRandomValues(new Uint8Array(12)); // 12 bytes IV for AES-GCM
                const passwordHash = await hashPassword(password);
                const key = await deriveKey(passwordHash, salt);

                const encodedMessage = stringToArrayBuffer(finalResult);
                const cipherText = await crypto.subtle.encrypt(
                    { name: "AES-GCM", iv: iv },
                    key,
                    encodedMessage
                );

                // Convert to base64 for easier handling
                const base64CipherText = btoa(String.fromCharCode(...new Uint8Array(cipherText)));
                const base64Salt = btoa(String.fromCharCode(...salt));
                const base64Iv = btoa(String.fromCharCode(...iv));

                // Concatenate the salt, iv, and ciphertext in the output format (without the password hash)
                finalResult = `${base64Salt}.${base64Iv}.${base64CipherText}`;
            }

            let baconOutput = '';

            // Convert input text to Bacon Cipher using the offset table
            for (const char of finalResult) {
                baconOutput += baconCipherKeyWithOffset[char] || ''; // Use logical OR to skip characters not in the key
            }
            if (inver == 0) {baconOutput = baconOutput.replace(/A/g, '.').replace(/B/g, '-');}
            else{baconOutput = baconOutput.replace(/A/g, '-').replace(/B/g, '.');}
            let output = '';
            for (let i = 0; i < baconOutput.length;) {
                let morseChar = '';
                let found = false;

                // Check for the longest valid Morse code character
                for (let j = 1; j <= 5 && i + j <= baconOutput.length; j++) {
                    const subStr = baconOutput.substring(i, i + j);
                    if (morseCodeMapWithOffset[subStr] !== undefined) {
                        morseChar = subStr; // Update morseChar to the latest valid substring
                        found = true; // Mark that we found a valid Morse code character
                    }
                }

                if (found) {
                    output += morseCodeMapWithOffset[morseChar]; // Append the corresponding character to output
                    i += morseChar.length; // Move the index forward by the length of the found Morse code
                } else {
                    i++; // If no valid Morse code was found, just move to the next character
                }
            }
            finalResult = output; // Update finalResult with the output of this iteration
        } else if (action === "decode") {
            let output = '';

            // Reverse the morseCodeMap to create a lookup for decoding
            const reverseMorseCodeMap = Object.fromEntries(
                Object.entries(morseCodeMapWithOffset).map(([morse, char]) => [char, morse])
            );

            // Convert each character to Morse code
            for (let char of finalResult) {
                if (reverseMorseCodeMap[char]) {
                    output += reverseMorseCodeMap[char]; // No space between Morse codes
                }
            }

            // Convert '.' to 'A' and '-' to 'B'
            if (inver == 0) {output = output.replace(/\./g, 'A').replace(/-/g, 'B');}
            else {output = output.replace(/\./g, 'B').replace(/-/g, 'A');}
            
            console.log("more " + output);
            const reverseBaconCipherKey = Object.fromEntries(
                Object.entries(baconCipherKeyWithOffset).map(([key, value]) => [value, key])
            );

            // Split the input string into chunks of 6 characters
            const chunks = output.match(/.{1,7}/g);
            
            // Decode each chunk using the reverse cipher key
            const decodedCharacters = chunks.map(chunk => reverseBaconCipherKey[chunk] || '');
            
            // Join the decoded characters into a final string
            finalResult = decodedCharacters.join('');

            if (password !== undefined && password !== "") {
                console.log("noPass");
                const parts = finalResult.split('.');
                
                const salt = new Uint8Array(atob(parts[0]).split("").map(c => c.charCodeAt(0)));
                const iv = new Uint8Array(atob(parts[1]).split("").map(c => c.charCodeAt(0)));
                const cipherText = new Uint8Array(atob(parts[2]).split("").map(c => c.charCodeAt(0)));

                const hashedPassword = await hashPassword(password);
                const key = await deriveKey(hashedPassword, salt);

                try {
                    const decrypted = await crypto.subtle.decrypt(
                        { name: "AES-GCM", iv: iv },
                        key,
                        cipherText
                    );
                    finalResult = arrayBufferToString(decrypted);
                } catch (e) {
                    console.error("Decryption failed", e);
                    finalResult = "Decryption failed!";
                }
            } else {
                finalResult = finalResult; // If no password, return the decoded message
            }
        } else {
            return "Invalid action!";
        }
    }

    return finalResult; // Return the final result at the end
}