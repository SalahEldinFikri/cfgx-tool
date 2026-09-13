from cfgx.algorithms.rc4 import rc4


data = b"Hello World"
key = b"secret"

encrypted = rc4(data, key)
decrypted = rc4(encrypted, key)

print("Encrypted:", encrypted.hex())
print("Decrypted:", decrypted)