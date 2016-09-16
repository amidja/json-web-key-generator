package org.mitre.simply.encryption;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.isEmptyOrNullString;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.support.AnnotationConfigContextLoader;

@RunWith(SpringJUnit4ClassRunner.class)
//ApplicationContext will be loaded from the AESEncryptionConfig class
@ContextConfiguration(classes=EncryptionConfig.class, loader=AnnotationConfigContextLoader.class)
public class HashCreatorTest {
	
	private static final Logger logger = LoggerFactory.getLogger(HashCreatorTest.class);

	@Autowired
	@Qualifier("hashMD5Creator")
	private HashCreator hashCreator;
	
	@Autowired
	@Qualifier("hashSaltedSHA160Creator")
	private HashCreator hashSaltedCreator;
		
	@Test
	public void testHashMD5Creator_hash() {
		String generatedHash = hashCreator.hash("secret");
		logger.debug("Generated Hash Value [{}]", generatedHash);
		assertThat(generatedHash, not(isEmptyOrNullString()));
	}
	
	@Test
	public void testHashSaltedSHA160Creator_hash() {
		String generatedHash = hashSaltedCreator.hash("secret");
		logger.debug("Generated Hash Value [{}]", generatedHash);
		assertThat(generatedHash, not(isEmptyOrNullString()));
	}	
}