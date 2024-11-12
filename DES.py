from Crypto.Random import get_random_bytes
from Crypto.Cipher import DES3, DES, AES

# Pedir los strings al usuario
key_des = input("Introduce la clave para DES (8 bytes): ")
vi_des = input("Introduce el vector de inicialización para DES (8 bytes): ")
key_aes = input("Introduce la clave para AES-256 (32 bytes): ")
vi_aes = input("Introduce el vector de inicialización para AES-256 (16 bytes): ")
key_3des = input("Introduce la clave para 3DES (24 bytes): ")
vi_3des = input("Introduce el vector de inicialización para 3DES (8 bytes): ")

texto_a_cifrar = input("Introduce el texto a cifrar: ")

# Ajuste de la clave para DES
if len(key_des.encode()) < 8:
    key_des = key_des.encode() + get_random_bytes(8 - len(key_des.encode()))
elif len(key_des.encode()) > 8:
    key_des = key_des.encode()[:8]
else:
    key_des = key_des.encode()

if len(vi_des.encode()) < 8:
    vi_des = vi_des.encode() + get_random_bytes(8 - len(vi_des.encode()))
elif len(vi_des.encode()) > 8:
    vi_des = vi_des.encode()[:8]
else:
    vi_des = vi_des.encode()

# Ajuste de la clave para AES-256
if len(key_aes.encode()) < 32:
    key_aes = key_aes.encode() + get_random_bytes(32 - len(key_aes.encode()))
elif len(key_aes.encode()) > 32:
    key_aes = key_aes.encode()[:32]
else:
    key_aes = key_aes.encode()

if len(vi_aes.encode()) < 16:
    vi_aes = vi_aes.encode() + get_random_bytes(16 - len(vi_aes.encode()))
elif len(vi_aes.encode()) > 16:
    vi_aes = vi_aes.encode()[:16]
else:
    vi_aes = vi_aes.encode()

# Ajuste de la clave para 3DES
if len(key_3des.encode()) < 24:
    key_3des = key_3des.encode() + get_random_bytes(24 - len(key_3des.encode()))
elif len(key_3des.encode()) > 24:
    key_3des = key_3des.encode()[:24]
else:
    key_3des = key_3des.encode()

if len(vi_3des.encode()) < 8:
    vi_3des = vi_3des.encode() + get_random_bytes(8 - len(vi_3des.encode()))
elif len(vi_3des.encode()) > 8:
    vi_3des = vi_3des.encode()[:8]
else:
    vi_3des = vi_3des.encode()

# Cifrado y Descifrado con DES
cipher_des = DES.new(key_des, DES.MODE_CBC, vi_des)
padding_length_des = 8 - (len(texto_a_cifrar.encode()) % 8)
texto_a_cifrar_padded_des = texto_a_cifrar.encode() + bytes([padding_length_des] * padding_length_des)
ciphertext_des = cipher_des.encrypt(texto_a_cifrar_padded_des)
decryptor_des = DES.new(key_des, DES.MODE_CBC, vi_des)
decrypted_des = decryptor_des.decrypt(ciphertext_des)
plaintext_des = decrypted_des[:-decrypted_des[-1]].decode()

# Cifrado y Descifrado con AES-256
cipher_aes = AES.new(key_aes, AES.MODE_CBC, vi_aes)
padding_length_aes = 16 - (len(texto_a_cifrar.encode()) % 16)
texto_a_cifrar_padded_aes = texto_a_cifrar.encode() + bytes([padding_length_aes] * padding_length_aes)
ciphertext_aes = cipher_aes.encrypt(texto_a_cifrar_padded_aes)
decryptor_aes = AES.new(key_aes, AES.MODE_CBC, vi_aes)
decrypted_aes = decryptor_aes.decrypt(ciphertext_aes)
plaintext_aes = decrypted_aes[:-decrypted_aes[-1]].decode()

# Cifrado y Descifrado con 3DES
cipher_3des = DES3.new(key_3des, DES3.MODE_CBC, vi_3des)
padding_length_3des = 8 - (len(texto_a_cifrar.encode()) % 8)
texto_a_cifrar_padded_3des = texto_a_cifrar.encode() + bytes([padding_length_3des] * padding_length_3des)
ciphertext_3des = cipher_3des.encrypt(texto_a_cifrar_padded_3des)
decryptor_3des = DES3.new(key_3des, DES3.MODE_CBC, vi_3des)
decrypted_3des = decryptor_3des.decrypt(ciphertext_3des)
plaintext_3des = decrypted_3des[:-decrypted_3des[-1]].decode()

print(f"\nClave ajustada para DES: {key_des}")
print(f"Vector de inicialización ajustado para DES: {vi_des}")
print(f"Texto cifrado con DES (en hexadecimal): {ciphertext_des.hex()}\n")
print(f"Texto descifrado con DES: {plaintext_des}")

print(f"\nClave ajustada para AES-256: {key_aes}")
print(f"Vector de inicialización ajustado para AES-256: {vi_aes}")
print(f"Texto cifrado con AES-256 (en hexadecimal): {ciphertext_aes.hex()}\n")
print(f"Texto descifrado con AES-256: {plaintext_aes}")

print(f"\nClave ajustada para 3DES: {key_3des}")
print(f"Vector de inicialización ajustado para 3DES: {vi_3des}")
print(f"Texto cifrado con 3DES (en hexadecimal): {ciphertext_3des.hex()}\n")
print(f"Texto descifrado con 3DES: {plaintext_3des}")
