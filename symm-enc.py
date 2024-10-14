import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

TEST_SAMPLES = {
    
    "AES-128": { 
        "key": "edfdb257cb37cdf182c5455b0c0efebb",
        "plaintext": "1695fe475421cace3557daca01f445ff",
        "ciphertext": "7888beae6e7a426332a7eaa2f808e637"
    },

    ## ECB segue um padrão
    "AES-128-ECB": {
        "key": "7723d87d773a8bbfe1ae5b081235b566",
        "plaintext": "1b0a69b7bc534c16cecffae02cc5323190ceb413f1db3e9f0f79ba654c54b60e",
        "ciphertext": "ad5b089515e7821087c61652dc477ab1f2cc6331a70dfc59c9ffb0c723c682f6"
    },

    ## CBC é chaining, uma encriptação depende da anterior, no padrões
    "AES-128-CBC": {
        "key": "0700d603a1c514e46b6191ba430a3a0c",
        "iv": "aad1583cd91365e3bb2f0c3430d065bb",
        "plaintext": "068b25c7bfb1f8bdd4cfc908f69dffc5ddc726a197f0e5f720f730393279be91",
        "ciphertext": "c4dc61d9725967a3020104a9738f23868527ce839aab1752fd8bdb95a82c4d00"
    }
}

def sample(sample_name):
    sample = TEST_SAMPLES.get(sample_name)
    if sample is None:
        raise ValueError("Invalid sample name")
    return (sample.get("key"), sample.get("plaintext"), sample.get("ciphertext"))

if __name__ == "__main__":
    print("Testings")
    print("-------------------------------------------------------------")

    for sample_name in TEST_SAMPLES:
        key, plaintext, ciphertext = sample(sample_name)
        print("Sample: {}".format(sample_name))
        print("Key: {}".format(key))
        print("Plaintext: {}".format(plaintext))
        print("Ciphertext: {}".format(ciphertext))

        key = bytes.fromhex(key)
        plaintext = bytes.fromhex(plaintext)
        if sample_name == "AES-128-ECB":
            cipher = Cipher(algorithms.AES(key), modes.ECB())
        elif sample_name == "AES-128-CBC":
            cipher = Cipher(algorithms.AES(key), modes.CBC(bytes.fromhex(TEST_SAMPLES.get("AES-128-CBC").get("iv"))))
        else:
            print("Considerar CBC com iv = 0")
            cipher = Cipher(algorithms.AES(key), modes.CBC(bytes.fromhex("0"*32)))
        
        encryptor = cipher.encryptor()
        ct = encryptor.update(plaintext) + encryptor.finalize()
        decryptor = cipher.decryptor()
        pt = decryptor.update(ct) + decryptor.finalize()
        deciphered = pt.hex()
        print("Deciphered: {}".format(deciphered))
        if deciphered == plaintext.hex():
            print("\n Text deciphered correctly!!!")

        print("---------------------------------------------------------") 