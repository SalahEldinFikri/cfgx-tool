from cfgx.crypto import aes_decrypt, unpad_pkcs7

def decrypt(data, key, iv):          # $config -> data, $key -> key, $iv -> iv
    return unpad_pkcs7(aes_decrypt(data, key, "CBC", iv))
