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
		
	 //Add salt	
    protected static byte[] getSalt() throws NoSuchAlgorithmException, NoSuchProviderException{
        //Always use a SecureRandom generator
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG", "SUN");
        
        //Create array for salt
        byte[] salt = new byte[16];

        //Get a random salt
        sr.nextBytes(salt);

        return salt;
    }	
}