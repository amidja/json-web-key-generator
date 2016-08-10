package org.mitre.simply.encryption.aes;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;
import org.mitre.simply.encryption.Encryptor;
import org.mitre.simply.encryption.PwdAESKeyGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AESEncryptionService extends PwdAESKeyGenerator implements Encryptor{
	
	private static Logger logger = LoggerFactory.getLogger(AESEncryptionService.class);
	    
    private String decryptedString;    
    private String encryptedString;
            
    public AESEncryptionService(String secret){
    	super(secret);
    }
    
    @Override
    public String encrypt(final String strToEncrypt) throws GeneralSecurityException{
    	encryptedString = null;
        try{
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");        
            cipher.init(Cipher.ENCRYPT_MODE, getSecretKey()); 
            byte[] ecnryptedByt = cipher.doFinal(strToEncrypt.getBytes(DEFAULT_CHAR_ENCODING));
            setEncryptedString(ecnryptedByt);        
        }catch (GeneralSecurityException es){           
        	logger.error("Error while encrypting: "+es.toString());
        	throw es;
        }catch (UnsupportedEncodingException ee){
        	logger.error("Error while encrypting: "+ee.toString());
        }
        return encryptedString;
    }
        
    @Override
    public String decrypt(final String strToDecrypt){    	      
        try{
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
           
            cipher.init(Cipher.DECRYPT_MODE, getSecretKey());
            byte[] decryptedByt = cipher.doFinal(Base64.decodeBase64(strToDecrypt));            
            setDecryptedString(decryptedByt);            
        }catch (GeneralSecurityException e){         
        	logger.error("Error while decrypting: "+e.toString());
        	decryptedString = null;
        }
        return decryptedString;
    }
    
    
    public String getDecryptedString() {return decryptedString;}    
    public String getEncryptedString() {return encryptedString;}
        
    private void setDecryptedString(byte[] dcryptdByt) {
        decryptedString = new String (dcryptdByt);
    }
    
    private void setEncryptedString(byte[] encryptdByt) {
    	encryptedString = Base64.encodeBase64String(encryptdByt);
    }
}