package org.mitre.simply.encryption.aes;

import static org.junit.Assert.assertEquals;

import java.security.GeneralSecurityException;

import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.simply.encryption.Encryptor;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@Ignore
@RunWith(SpringJUnit4ClassRunner.class)
//ApplicationContext will be loaded from the OrderServiceConfig class
//@ContextConfiguration(classes=OrderServiceConfig.class, loader=AnnotationConfigContextLoader.class)
public class AESEncryptionTest {

	private final String strToEncrypt = "My text to encrypt";
    private final String strPssword = "encryptor key";
	
	@Test
	public void testEncrypt() throws GeneralSecurityException{
		Encryptor encryptor = new AESEncryptionService(strPssword); 
				        
        System.out.println("String to Encrypt: " + strToEncrypt); 
        System.out.println("Encrypted: " + encryptor.encrypt(strToEncrypt.trim()));         
	}
	
	@Test
	public void testDecrypt() throws GeneralSecurityException{

		AESEncryptionService aesEncryption = new AESEncryptionService(strPssword);
               
        System.out.println("String to Encrypt: " + strToEncrypt); 
        System.out.println("Encrypted: " + aesEncryption.encrypt(strToEncrypt));
   
        String strDecrypted =  aesEncryption.decrypt(aesEncryption.encrypt(strToEncrypt));
                
        System.out.println("Decrypted : " + strDecrypted);
        assertEquals(strToEncrypt, strDecrypted);
	}	
}
