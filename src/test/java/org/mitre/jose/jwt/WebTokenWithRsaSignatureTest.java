package org.mitre.jose.jwt;

import static org.junit.Assert.assertTrue;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

import org.junit.BeforeClass;
import org.junit.Test;
import org.mitre.jose.jwk.RSAKeyMaker;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public class WebTokenWithRsaSignatureTest {

	private static final String KID = "vaadwaur-pulsewave";

	private static final JWSAlgorithm KEY_ALG = JWSAlgorithm.RS512;
	
	private static RSAKey myRsaKey;

	@BeforeClass 
	public static void onlyOnce() {
		// Create RSA keys
		myRsaKey = getRsaKey(KID, KEY_ALG);
	}

	@Test
	public void testJwkWithRsaSignature() throws Exception {

		// Create RSA keys
		RSAKey myRsaKey = getRsaKey(KID, KEY_ALG);

		RSAPublicKey publicKey = myRsaKey.toRSAPublicKey();
		RSAPrivateKey privateKey = myRsaKey.toRSAPrivateKey();

		// Create RSA-signer with the private key
		JWSSigner signer = new RSASSASigner(privateKey);

		// Prepare JWT with claims set
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().issuer("organisation_id").subject(KID).issueTime(new Date())
				.expirationTime(new Date(new Date().getTime() + 60 * 1000)).build();

		SignedJWT signedJWT = new SignedJWT(new JWSHeader(KEY_ALG), claimsSet);

		// Compute the RSA signature
		signedJWT.sign(signer);

		// To serialize to compact form, produces something like
		// eyJhbGciOiJSUzI1NiJ9.SW4gUlNBIHdlIHRydXN0IQ.IRMQENi4nJyp4er2L
		// mZq3ivwoAjqa1uUkSBKFIX7ATndFF5ivnt-m8uApHO4kfIFOrW7w2Ezmlg3Qd
		// maXlS9DhN0nUk_hGI3amEjkKd0BWYCB8vfUbUv0XGjQip78AI4z1PrFRNidm7
		// -jPDm5Iq0SZnjKjCNS5Q15fokXZc8u0A
		String strSignedJwt = signedJWT.serialize();

		System.out.println("Signed JWT : " + strSignedJwt);

		// On the consumer side, parse the JWS and verify its RSA signature
		signedJWT = SignedJWT.parse(strSignedJwt);

		JWSVerifier verifier = new RSASSAVerifier(publicKey);
		assertTrue(signedJWT.verify(verifier));
	}

	private static RSAKey getRsaKey(String kid, Algorithm keyAlg) {

		String size = "2048";
		KeyUse keyUse = KeyUse.SIGNATURE;

		Integer keySize = Integer.decode(size);
		RSAKey jwk = RSAKeyMaker.make(keySize, keyUse, keyAlg, kid);

		return jwk;
	}

}
