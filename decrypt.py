from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Protocol import KDF

KEY_SIZE_BYTES = 32;
PBKDF2_ITERATIONS  = 50000

password = ""
encryption_iv = ""
encryption_salt = "="
encryptedData = ""

def get_encryption_key(password: str, salt: str):
    #based on https://github.com/Jessecar96/SteamDesktopAuthenticator/blob/8a408f13ee24f70fffbc409cb0e050e924f4fe94/Steam%20Desktop%20Authenticator/FileEncryptor.cs#L72
    return KDF.PBKDF2(password, b64decode(encryption_salt), dkLen=KEY_SIZE_BYTES, count=PBKDF2_ITERATIONS)


def decrypt(data):
    #based on https://github.com/Jessecar96/SteamDesktopAuthenticator/blob/8a408f13ee24f70fffbc409cb0e050e924f4fe94/Steam%20Desktop%20Authenticator/FileEncryptor.cs#L87
    cipher_text = b64decode(data)
    key = get_encryption_key(password, encryption_salt)

    unpad = lambda s: s[:-ord(s[len(s) - 1:])] #replaces aes_padding
    
    aes_iv = b64decode(encryption_iv)
    aes_key = key #no idea why this is done like this but i'm replicating the src
    aes_padding = None
    aes_mode = AES.MODE_CBC
    
    aes_decrypter = AES.new(aes_key, aes_mode, aes_iv)
    cipher_text = aes_decrypter.decrypt(b64decode(data))
    return unpad(cipher_text)

def main():
    plain_text = decrypt(encryptedData)
    print(plain_text)
    
    
    
if __name__ == "__main__":
    main()
