package org.mitre.simply.encryption;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PwdPBEKeyGenerator implements PwdKeyGenerator{
	
	private Logger logger = LoggerFactory.getLogger(PwdAESKeyGenerator.class);
	
    private SecretKeySpec secretKey ;
            
    public PwdPBEKeyGenerator(String pwd){
    	deriveKey(pwd);    	
    }
    
	@Override
	public SecretKeySpec deriveKey(String pwd) {
		final byte[] key = this.deriveByteKey(pwd, DEFAULT_KEY_LENGTH);
		secretKey = new SecretKeySpec(key, DEFAULT_KEY_ALGORITHM);
		return secretKey;
	}
    
    /**
     * This method uses PBKDF2 with SHA1 HMAC to generate a key
     */	
	private byte[] deriveByteKey(String pwd, KeyLengthType keyLength) {
		byte[] pwdKey = null;
		try{
        	// Generate 160 bit Salt for Encryption Key
    		SecureRandom r = SecureRandom.getInstance("SHA1PRNG");        
        	byte[] esalt = new byte[20]; r.nextBytes(esalt);   
        	
        	// Generate 128 bit Encryption Key       	    	
        	PBEKeySpec ks = new PBEKeySpec(pwd.toCharArray(), esalt, 100000, keyLength.getLength());           	
        	SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");   
        	
        	pwdKey = skf.generateSecret(ks).getEncoded();	
    	} catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InvalidKeySpecException ee) {
            // TODO Auto-generated catch block
            ee.printStackTrace();
        }   
		return pwdKey;
	}

	
	public SecretKeySpec getSecretKey(){return secretKey;}
	
}