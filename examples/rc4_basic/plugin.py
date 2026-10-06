from cfgx.crypto import rc4

def decrypt(data, key):
    return rc4(data, key)
