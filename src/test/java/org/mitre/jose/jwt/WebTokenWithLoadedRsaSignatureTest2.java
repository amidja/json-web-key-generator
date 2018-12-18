package org.mitre.jose.jwt;

import static org.junit.Assert.assertTrue;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

import org.junit.Ignore;
import org.junit.Test;
import org.me.java.security.PemFile;
import org.mitre.jose.jwk.RSAKeyMaker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

public class WebTokenWithLoadedRsaSignatureTest2 {

	final static Logger LOGGER = LoggerFactory.getLogger(WebTokenWithLoadedRsaSignatureTest2.class);
	
	private String resourcesFilePath = "src/test/resources/";

	//private static final JWSAlgorithm KEY_ALG = JWSAlgorithm.RS512;
	//private static final String KID = "varon-t-disruptor";
	//private static final String ORGID = "9646844092";
	
	private static final String KID = "vaadwaur-pulsewave";
	private static final String ORGID = "9646844092";
	private static final JWSAlgorithm KEY_ALG = JWSAlgorithm.RS512;
		
	@Test
	public void testJwkWithRsaSignature() throws Exception {

		RSAKey myRsaKey = loadRSAKeyFromFile(KID.trim());

		RSAPublicKey publicKey = myRsaKey.toRSAPublicKey();
		RSAPrivateKey privateKey = myRsaKey.toRSAPrivateKey();

		// Create RSA-signer with the private key
		JWSSigner signer = new RSASSASigner(privateKey);

		// Prepare JWT with claims set
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
				.issuer(ORGID)
				.subject(KID)
				.audience("https://proda.humanservices.gov.au")
				.issueTime(new Date())
				.expirationTime(new Date(new Date().getTime() + 60 * 1000)).build();

		JWSHeader myJWSHeader = new JWSHeader.Builder(KEY_ALG).keyID(KID).build();

		SignedJWT signedJWT = new SignedJWT(myJWSHeader, claimsSet);

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

	@Test
	public void testPemFileCreation() throws Exception {
		RSAKey myRsaKey = loadRSAKeyFromFile(KID.trim());
		
		outPemFiles(myRsaKey, KID.trim());		
	}
	
	/*
	 * The method will create new JWK and write it to a file for a new device
	 */
	public RSAKey loadRSAKeyFromFile(String deviceName) throws Exception {
	
		RSAKey myRsaKey = null;

		String fileJwkName = resourcesFilePath + deviceName + ".jwk";
		String filePubJwkName = resourcesFilePath + deviceName + "-pub.jwk";

		// URL jwkFileLocation = classLoader.getResource(fileJwkName);

		// if (jwkFileLocation == null) {
		LOGGER.debug(" Creating new JWK for {} ", deviceName);

		File newJwkFile = new File(fileJwkName);
		if (newJwkFile.createNewFile()) {
			myRsaKey = getRsaKey(KID, KEY_ALG);
			BufferedWriter writer = new BufferedWriter(new FileWriter(newJwkFile));
			writer.write(myRsaKey.toJSONString());
			writer.close();
			// create public key
			File newPubJwkFile = new File(filePubJwkName);
			newPubJwkFile.createNewFile();
			writer = new BufferedWriter(new FileWriter(newPubJwkFile));
			writer.write(myRsaKey.toPublicJWK().toJSONString()); 
			writer.close();
		} else {
			LOGGER.debug(" File {} exist", fileJwkName);
			BufferedReader reader = new BufferedReader(new FileReader(fileJwkName));
			StringBuilder builder = new StringBuilder();
			String currentLine = reader.readLine();

			while (currentLine != null) {
				builder.append(currentLine);
				currentLine = reader.readLine();
			}
			reader.close();
			myRsaKey = RSAKey.parse(builder.toString());
		}

		return myRsaKey;
	}

	private static RSAKey getRsaKey(String kid, Algorithm keyAlg) {

		String size = "3072";
		KeyUse keyUse = KeyUse.SIGNATURE;

		Integer keySize = Integer.decode(size);
		RSAKey jwk = RSAKeyMaker.make(keySize, keyUse, keyAlg, kid);

		return jwk;
	}

	private void outPemFiles(RSAKey rsaKey, String deviceName) throws Exception {
		String privateFileName = resourcesFilePath + deviceName + "-private.pem";
		String publicFileName = resourcesFilePath + deviceName + "-public.pem";
		
		PemFile pemFile = new PemFile(rsaKey.toPrivateKey(), "PRIVATE KEY");		
		pemFile.write(privateFileName);
		
		pemFile = new PemFile(rsaKey.toPublicKey(), "PUBLIC KEY");		
		pemFile.write(publicFileName);		
	}
}
