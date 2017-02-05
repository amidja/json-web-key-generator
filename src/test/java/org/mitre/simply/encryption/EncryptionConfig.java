package org.mitre.simply.encryption;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan(basePackages = { "org.mitre.simply.encryption" })
public class EncryptionConfig {
	
	private static final Logger logger = LoggerFactory.getLogger(EncryptionConfig.class);
			
	
	@Bean
	HashBasicCreator hashMD5Creator(){
		HashBasicCreator hashBasicCreator = new HashBasicCreator();
		hashBasicCreator.setAlgorithm("MD5");
		return hashBasicCreator;
	}
	
	
	//	Java has 4 implementations of SHA algorithm. 
	//	They generate following length hashes in comparison to MD5 (128 bit hash):	
	//
	//   SHA-1 (Simplest one � 160 bits Hash)
	//   SHA-256 (Stronger than SHA-1 � 256 bits Hash)
	//   SHA-384 (Stronger than SHA-256 � 384 bits Hash)
	//   SHA-512 (Stronger than SHA-384 � 512 bits Hash)
	@Bean
	HashSaltedCreator hashSaltedSHA160Creator(){
		HashSaltedCreator hashSaltedCreator = new HashSaltedCreator();
		hashSaltedCreator.setAlgorithm("SHA-1");
		return hashSaltedCreator;
	}
	
	
	/*public static void main(String[] args) {
		ApplicationContext context =  new AnnotationConfigApplicationContext(EncryptionConfig.class);
		AESEncryptionService encryptor = context.getBean(AESEncryptionService.class);
		
		try{
			encryptor.encrypt("Hello World!");  		
		}catch(GeneralSecurityException exception){
	    	  logger.error(exception.toString());
		}
	}*/
}
