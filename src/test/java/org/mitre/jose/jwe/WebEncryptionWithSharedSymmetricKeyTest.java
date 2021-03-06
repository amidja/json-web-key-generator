package org.mitre.jose.jwe;

import static org.junit.Assert.assertEquals;

import java.security.Security;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;

public class WebEncryptionWithSharedSymmetricKeyTest {
	
	private static String strSharedKey = "This is the key";
	
	// The shared byte key
	static final byte[] key128 = {
	(byte)177, (byte)119, (byte) 33, (byte) 13, (byte)164, (byte) 30, (byte)108, (byte)121,
	(byte)207, (byte)136, (byte)107, (byte)242, (byte) 12, (byte)224, (byte) 19, (byte)226 };


	@Test
	public void testEncryptionWihtSharedByteKey() throws Exception{
		//A128GCM Encryption is only supported in Java8
		//Adding BouncyCastle to the list of security providers 
		Security.addProvider(new BouncyCastleProvider());
		// Create the header
		JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128GCM);

		// Set the plain text
		Payload payload = new Payload("Hello world!");

		// Create the JWE object and encrypt it
		JWEObject jweObject = new JWEObject(header, payload);		
		jweObject.encrypt(new DirectEncrypter(key128));

		// Serialise to compact JOSE form...
		String jweString = jweObject.serialize();

		// Parse into JWE object again...
		jweObject = JWEObject.parse(jweString);

		// Decrypt
		jweObject.decrypt(new DirectDecrypter(key128));

		// Get the plain text
		payload = jweObject.getPayload();
		assertEquals("Hello world!", payload.toString());
	}
	
	
	@Test
	public void testEncryptionWihtSharedSecretKey() throws Exception{
		//A128GCM Encryption is only supported in Java8
		//Adding BouncyCastle to the list of security providers 
		Security.addProvider(new BouncyCastleProvider());
										
	    byte[] encodedKey = Base64.encodeBase64(strSharedKey.getBytes("UTF-8"));
	    encodedKey = Arrays.copyOf(encodedKey, 16);//using only first 128 bits
	    
	    //System.out.println(ByteUtils.bitLength(encodedKey));
	    	    
	    SecretKey secretKey = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
	    
		// Create the header
		JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128GCM);

		// Set the plain text
		Payload payload = new Payload("Hello world!");

		// Create the JWE object and encrypt it
		JWEObject jweObject = new JWEObject(header, payload);
		
		jweObject.encrypt(new DirectEncrypter(secretKey));

		// Serialise to compact JOSE form...
		String jweString = jweObject.serialize();

		// Parse into JWE object again...
		jweObject = JWEObject.parse(jweString);

		// Decrypt
		jweObject.decrypt(new DirectDecrypter(secretKey));

		// Get the plain text
		payload = jweObject.getPayload();
		assertEquals("Hello world!", payload.toString());
	}
	
					
	/**
	 * 
	 * @param pwd
	 * @param salt
	 * @param iterationCount
	 * @param length
	 * @return
	 */
	private byte[] deriveKey(String pwd, byte[] salt, int iterationCount, int length){
		
		
		return null;
	}
	
	

}
