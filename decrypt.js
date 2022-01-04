import crypto from "crypto"

const PBKDF2_ITERATIONS = 50000; //Set to 50k to make program not unbearably slow. May increase in future.
const SALT_LENGTH = 8;
const KEY_SIZE_BYTES = 32;
const IV_LENGTH = 16;


const password = '';
const encryptedData = '';
const encryptionSalt = '';
const encryptionIv = '';

/**
 * Based on https://github.com/Jessecar96/SteamDesktopAuthenticator/blob/8a408f13ee24f70fffbc409cb0e050e924f4fe94/Steam%20Desktop%20Authenticator/FileEncryptor.cs#L72
 */
function getEncryptionKey(password, salt) {
    return new Promise(resolve => {
        crypto.pbkdf2(password, Buffer.from(salt, 'base64'), PBKDF2_ITERATIONS, KEY_SIZE_BYTES, 'sha1', ((err, derivedKey) => {
            resolve(derivedKey)
        }))
    })
}

/**
 * Based on https://github.com/Jessecar96/SteamDesktopAuthenticator/blob/8a408f13ee24f70fffbc409cb0e050e924f4fe94/Steam%20Desktop%20Authenticator/FileEncryptor.cs#L87
 *
 * @param password Your encryption password.
 * @param encryptionSalt `encryption_salt` in manifest.json
 * @param encryptionIv `encryption_iv` in manifest.json
 * @param encryptedData Content of the encrypted .maFile
 */
async function decryptData(password, encryptionSalt, encryptionIv, encryptedData) {
    const key = await getEncryptionKey(password, encryptionSalt)

    const decrypter = crypto.createDecipheriv("aes-256-cbc", key, Buffer.from(encryptionIv, 'base64'));

    return decrypter.update(encryptedData, "base64", "utf8") + decrypter.final("utf8");
}

async function main() {
    const plaintext = await decryptData(password, encryptionSalt, encryptionIv, encryptedData);
    console.log(plaintext)
}

main()
