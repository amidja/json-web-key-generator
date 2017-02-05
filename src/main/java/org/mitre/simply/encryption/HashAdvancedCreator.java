package org.mitre.simply.encryption;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;


//http://howtodoinjava.com/security/how-to-generate-secure-password-hash-md5-sha-pbkdf2-bcrypt-examples/#md5

/**
 * Advanced password security using PBKDF2WithHmacSHA1 algorithm
 * 
 * Please note that now you have to store generated salt value for every password you hash. 
 * Because when user login back in system, you must use only originally generated salt to again 
 * create the hash to match with stored hash. 
 * 
 * If a different salt is used (we are generating random salt), then generated hash will be different.
 * 
 */
@Component("hashSaltedCreator")
public class HashAdvancedCreator extends HashSaltedCreator {

	private static final Logger logger = LoggerFactory.getLogger(HashAdvancedCreator.class);
	
	private static final int DEFAULT_NO_ITERATIONS = 1000;
	
	private int iterations = DEFAULT_NO_ITERATIONS;
		
	@Override
	public String hash(String strToHash)  {		
        char[] chars = strToHash.toCharArray();
        String strHashed = null;
        
        try{
        	byte[] salt = getSalt();
            
            PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, 64 * 8);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            byte[] hash = skf.generateSecret(spec).getEncoded();
            strHashed = iterations + ":" + toHex(salt) + ":" + toHex(hash);       	
        
        }catch(NoSuchAlgorithmException ex){
        	ex.printStackTrace();
        }catch(NoSuchProviderException ep){
        	ep.toString();
        }catch(InvalidKeySpecException ek){
        	ek.toString();
        }
        
        return strHashed;
	}

	
	public int getIterations() {
		return iterations;
	}

	public void setIterations(int iterations) {
		if (iterations < DEFAULT_NO_ITERATIONS)
			throw new IllegalArgumentException("no iterations must be larger than " + DEFAULT_NO_ITERATIONS);
		
		this.iterations = iterations;
	}
	
	private static String toHex(byte[] array) throws NoSuchAlgorithmException{
        BigInteger bi = new BigInteger(1, array);
        String hex = bi.toString(16);
        int paddingLength = (array.length * 2) - hex.length();
        
        if(paddingLength > 0){
            return String.format("%0"  +paddingLength + "d", 0) + hex;
        }else{
            return hex;
        }
    }
}