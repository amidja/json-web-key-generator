References 
======================
Home: https://bitbucket.org/connect2id/nimbus-jose-jwt/wiki/Home
Examples: http://connect2id.com/products/nimbus-jose-jwt/examples


json-web-key-generator
======================

A commandline Java-based generator for JSON Web Keys (JWK) and JSON Private/Shared Keys (JPSKs).

=====================

To compile, run `mvn package`. This will generate a json-web-key-generator-0.1-SNAPSHOT-jar-with-dependencies.jar in the /target directory. 

To generate a key, run `java -jar json-web-key-generator-0.1-SNAPSHOT-jar-with-dependencies.jar -t <keytype>`. Several other arguments are defined which may be required depending on your key type:

```
 -a <arg>   Algorithm (optional)
 -c <arg>   Key Curve, required for EC key type. Must be one of P-256,
            P-384, P-521
 -i <arg>   Key ID (optional)
 -p         Display public key separately
 -s <arg>   Key Size in bits, required for RSA and OCT key types. Must be
            an integer divisible by 8
 -t <arg>   Key Type, one of: RSA, oct, EC
 -u <arg>   Usage, one of: enc, sig (optional)
```


How to perform password based encryption and decryption of data:
=================================================================
AES Encryption: http://netnix.org/2015/04/19/aes-encryption-with-hmac-integrity-in-java/

1.Java only supports AES encryption with 128 bit keys out of the box – if you want 192 or 256 bit keys then you need to install the “Java JCE Unlimited Strength Jurisdiction Policy Files” for your version of Java. Every user of your tool will need to install them as well.

2.You should be using PBKDF2 (“bcrypt” and “scrypt” might be better alternatives, but Java doesn’t support them) to generate your secret key which takes your password and a pseudorandom salt and passes it through lots of iterations of a hashing algorithm to produce the final key. This can be time consuming and is supposed to make it time consuming for an attacker to brute force it.

3.AES encryption on its own doesn’t provide any integrity of the data (unless using GCM mode to provide Authenticated Encryption with Associated Data – AEAD) so it is recommended to use something like HMAC-SHA-256. The HMAC should be applied after encryption to provide protection to Padding Oracle Attacks.

4.You should really be using separate keys for AES encryption and the HMAC – if one of the algorithms is compromised then both are. You can generate separate keys from a master key using something like HKDF (RFC5869), but Java doesn’t provide an implementation.

5.The pseudorandom salt should be a cryptographically secure random number and should be at least the block size of your hashing algorithm (i.e. 160 bits for SHA-1).

6.Your key length should match your encryption/HMAC algorithm (i.e. 128 bits for AES-128 and 256 bits for HMAC-256).

7.If you are using the same secret key to encrypt multiple strings you should be using a random Initialisation Vector (IV) every time – this prevents the same key generating the same ciphertext from the same plaintext. You will also need to include the IV with the salt (they aren’t considered secret) when you store it as you need the same IV and salt for decryption. If you never use the same key twice then an IV is fairly redundant.

8.In the same sense, you may want to avoid using AES in ECB mode (as identical plaintext, when encrypted with the same key always outputs the same ciphertext) and stick with CBC (with PKCS#5 Padding) or CTR mode, but it really depends on your application
