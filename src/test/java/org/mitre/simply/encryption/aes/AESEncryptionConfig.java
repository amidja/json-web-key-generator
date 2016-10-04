package org.mitre.simply.encryption.aes;

import java.security.GeneralSecurityException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan(basePackages = { "org.mitre.simply.encryption.aes" })
public class AESEncryptionConfig {
	
	private static final Logger logger = LoggerFactory.getLogger(AESEncryptionConfig.class);
			
	@Bean
	String encryptionSecret(){
		return "password";
	}
		
	public static void main(String[] args) {
		ApplicationContext context =  new AnnotationConfigApplicationContext(AESEncryptionConfig.class);
		AESEncryptionService encryptor = context.getBean(AESEncryptionService.class);
		
		try{
			encryptor.encrypt("Hello World!");  		
		}catch(GeneralSecurityException exception){
	    	  logger.error(exception.toString());
		}
	}
}
