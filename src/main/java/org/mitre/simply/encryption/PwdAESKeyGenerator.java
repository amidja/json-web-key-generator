package org.mitre.simply.encryption;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class PwdAESKeyGenerator implements PwdKeyGenerator{
	
	private Logger logger = LoggerFactory.getLogger(PwdAESKeyGenerator.class);
			
    private SecretKeySpec secretKey ;
    
    public PwdAESKeyGenerator(String pwd){
    	this.deriveKey(pwd);
    }
                         
    @Override
	public SecretKeySpec deriveKey(String pwd){
    	final byte[] key = deriveByteKey(pwd, DEFAULT_KEY_LENGTH);
    	secretKey = new SecretKeySpec(key, DEFAULT_KEY_ALGORITHM);
		return secretKey;
	}
    
    /*Generates 128 bit encryption key*/    
    private byte[] deriveByteKey(String pwd, KeyLengthType keyLength){
    	MessageDigest sha = null;
        byte[] pwdKey = null;
        
        try {
        	pwdKey = pwd.getBytes(DEFAULT_CHAR_ENCODING);            
        	sha = MessageDigest.getInstance("SHA-1");
            pwdKey = sha.digest(pwdKey);
            pwdKey = Arrays.copyOf(pwdKey, (keyLength.getLength()/8));                   
                                               
            if (logger.isDebugEnabled()){
            	logger.debug("Key length is [{}]", pwdKey.length);
                logger.debug("UTF-8 Key is [{}]", new String(pwdKey, DEFAULT_CHAR_ENCODING));	
            }                        
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }                    
        
        return pwdKey;
    }
    
    public SecretKeySpec getSecretKey() { return secretKey;}
}