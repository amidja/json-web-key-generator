package org.mitre.simply.encryption.aes;

import static org.junit.Assert.assertEquals;

import java.security.GeneralSecurityException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.simply.encryption.Encryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.support.AnnotationConfigContextLoader;

@RunWith(SpringJUnit4ClassRunner.class)
//ApplicationContext will be loaded from the AESEncryptionConfig class
@ContextConfiguration(classes=AESEncryptionConfig.class, loader=AnnotationConfigContextLoader.class)
public class AESEncryptionTest {

	Logger logger = LoggerFactory.getLogger(AESEncryptionTest.class);
	
	private final String strToEncrypt = "My text to encrypt";
    private final String strPssword = "password";
    
    @Autowired
    private AESEncryptionService aesEncryptionService;
    
	@Test
	public void testEncrypt() throws GeneralSecurityException{
		Encryptor encryptor = new AESEncryptionService(strPssword); 
				        
        logger.info("String to Encrypt: " + strToEncrypt); 
        logger.info("Encrypted: " + encryptor.encrypt(strToEncrypt.trim()));         
	}
	
	@Test
	public void testDecrypt() throws GeneralSecurityException{
               
        logger.info("String to Encrypt: " + strToEncrypt); 
        logger.info("Encrypted: " + aesEncryptionService.encrypt(strToEncrypt));
   
        String strDecrypted =  aesEncryptionService.decrypt(aesEncryptionService.encrypt(strToEncrypt));
                
        logger.info("Decrypted : " + strDecrypted);
        assertEquals(strToEncrypt, strDecrypted);
	}	
}
