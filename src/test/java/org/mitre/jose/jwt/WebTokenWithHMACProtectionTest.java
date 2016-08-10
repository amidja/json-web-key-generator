package org.mitre.jose.jwt;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.security.SecureRandom;
import java.util.Date;

import org.junit.Test;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public class WebTokenWithHMACProtectionTest {

	@Test
	public void testHMACWebTokenProtection() throws Exception{
		// Generate random 256-bit (32-byte) shared secret
		SecureRandom random = new SecureRandom();
		byte[] sharedSecret = new byte[32];
		random.nextBytes(sharedSecret);

		// Create HMAC signer
		JWSSigner signer = new MACSigner(sharedSecret);
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
				.subject("alice")
				.issuer("https://c2id.com")				
				.expirationTime(new Date(1300819380 * 1000l)).build();

		
		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
		
		// Apply the HMAC protection
		signedJWT.sign(signer);
		
		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		System.out.println("Signed JWT:");
		System.out.println(gson.toJson(signedJWT));

		// Serialize to compact form, produces something like
		// eyJhbGciOiJIUzI1NiJ9.SGVsbG8sIHdvcmxkIQ.onO9Ihudz3WkiauDO2Uhyuz0Y18UASXlSc1eS0NkWyA
		String s = signedJWT.serialize();
		System.out.println("Serialized JWT:");
		System.out.println(s);
		
		// - - - - - - - - - - - - - - - - - - - - - - - - - - -  - - - -
		// On the consumer side, parse the JWS and verify its HMAC
		// - - - - - - - - - - - - - - - - - - - - - - - - - - -  - - - - 
		signedJWT = SignedJWT.parse(s);

		JWSVerifier verifier = new MACVerifier(sharedSecret);

		assertTrue(signedJWT.verify(verifier));

		// Retrieve / verify the JWT claims according to the app requirements
		assertEquals("alice", signedJWT.getJWTClaimsSet().getSubject());
		assertEquals("https://c2id.com", signedJWT.getJWTClaimsSet().getIssuer());	
	}
}
