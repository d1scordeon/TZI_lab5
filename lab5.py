import base64


def feistel_function(right, round_key):
    return (right + round_key) % 256


def pad_text(text):
    return text if len(text) % 2 == 0 else text + ' '


def encrypt(plain_text, keys):
    plain_text = pad_text(plain_text)

    cipher_text = ''
    for i in range(0, len(plain_text), 2):
        left, right = ord(plain_text[i]), ord(plain_text[i + 1])

        for key in keys:
            left, right = right, left ^ feistel_function(right, key)

        cipher_text += chr(left) + chr(right)

    return base64.b64encode(cipher_text.encode()).decode()


def decrypt(cipher_text, keys):
    cipher_text = base64.b64decode(cipher_text).decode()

    plain_text = ''
    for i in range(0, len(cipher_text), 2):
        left, right = ord(cipher_text[i]), ord(cipher_text[i + 1])

        for key in reversed(keys):
            right, left = left, right ^ feistel_function(left, key)

        plain_text += chr(left) + chr(right)

    return plain_text


# Example usage
keys = [1, 2, 3, 4, 5, 6, 7, 8]

plaintext = "HelloWorld"
ciphertext = encrypt(plaintext, keys)
print(f"Encrypted: {ciphertext}")

decrypted = decrypt(ciphertext, keys)
print(f"Decrypted: {decrypted}")
