package org.mitre.simply.encryption;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;


/**
 * 
 * Please note that now you have to store generated salt value for every password you hash. 
 * Because when user login back in system, you must use only originally generated salt to again 
 * create the hash to match with stored hash. 
 * 
 * If a different salt is used (we are generating random salt), then generated hash will be different.
 * 
 */
@Component("hashSaltedCreator")
public class HashSaltedCreator extends HashBasicCreator {

	private static final Logger logger = LoggerFactory.getLogger(HashSaltedCreator.class);
	
	private static String algorithm = "SHA1PRNG";
	private static String provider = "SUN";
	
	//Salt generation 64 bits long
	private static int saltLength = 8;

		
	 //Add salt	
    protected static byte[] getSalt() throws NoSuchAlgorithmException, NoSuchProviderException{
        //Always use a SecureRandom generator
        SecureRandom sr = SecureRandom.getInstance(algorithm, provider);        
        
        //Create array for salt
        byte[] salt = new byte[saltLength];

        //Get a random salt
        sr.nextBytes(salt);

        return salt;
    }	
}