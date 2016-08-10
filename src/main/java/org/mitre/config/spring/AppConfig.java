package org.mitre.config.spring;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan(basePackages = { "org.mitre.simply.encryption.aes" })
public class AppConfig {

	private static final Logger logger = LoggerFactory.getLogger(AppConfig.class);
	
	
}