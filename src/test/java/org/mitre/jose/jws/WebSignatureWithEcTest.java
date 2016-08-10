package org.mitre.jose.jws;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import org.junit.Test;
import org.mitre.jose.jwk.ECKeyMaker;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.ECKey.Curve;
import com.nimbusds.jose.jwk.KeyUse;

public class WebSignatureWithEcTest {

	@Test
	public void testHmacECSignature() throws Exception{
		// Create the public and private EC keys
		KeyUse keyUse = KeyUse.SIGNATURE;
		Algorithm keyAlg = JWSAlgorithm.HS512;
		Curve keyCurve = Curve.parse(Curve.P_256.getName());
					
		ECKey ecKey = ECKeyMaker.make(keyCurve, keyUse, keyAlg, null);
		
		ECPublicKey publicKey = ecKey.toECPublicKey();
		ECPrivateKey privateKey = ecKey.toECPrivateKey();
		
		// Create the EC signer
		JWSSigner signer = new ECDSASigner(privateKey);

		// Creates the JWS object with payload
		JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.ES256), new Payload("Elliptic cure"));
		
		// Compute the EC signature
		jwsObject.sign(signer);
		
		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		System.out.println("Signed JWS:");
		System.out.println(gson.toJson(jwsObject));

		// Serialize the JWS to compact form
		String s = jwsObject.serialize();
		System.out.println("Signed JWS in the compact format");
		System.out.println(s);

		// The recipient must create a verifier with the public 'x' and 'y' EC params		
		JWSVerifier verifier = new ECDSAVerifier(publicKey);

		 // Verify the EC signature
		assertTrue("ES256 signature verified", jwsObject.verify(verifier));
		assertEquals("Elliptic cure", jwsObject.getPayload().toString());				
	}
}

