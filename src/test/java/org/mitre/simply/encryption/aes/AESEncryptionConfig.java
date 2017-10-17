package org.mitre.simply.encryption.aes;

import java.security.GeneralSecurityException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AESEncryptionConfig {

	private static final Logger LOG = LoggerFactory.getLogger(AESEncryptionConfig.class);

	@Bean
	String encryptionSecret() {
		return "password";
	}
	
	@Bean
	AESEncryptionService getAESEncryptionService(){
		return new AESEncryptionService(encryptionSecret());
	}

	public static void main(String[] args) {
		
		ApplicationContext context = new AnnotationConfigApplicationContext(AESEncryptionConfig.class);
		
		AESEncryptionService encryptor = context.getBean(AESEncryptionService.class);

		try {
			encryptor.encrypt("Hello World!");
		} catch (GeneralSecurityException exception) {
			LOG.error(exception.toString());
		}
	}
}