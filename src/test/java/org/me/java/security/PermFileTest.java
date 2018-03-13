package org.me.java.security;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Key;

import org.junit.BeforeClass;
import org.mitre.jose.jwk.RSAKeyMaker;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

/*
 * Create public/private RSA keys and stores them to PEM files
 */
public class PermFileTest {

	private static final String ORGID = "vaadwaur-pulsewave";
	
	private static final String KID = "9646844092";

	private static final JWSAlgorithm KEY_ALG = JWSAlgorithm.RS256;

	private static RSAKey myRsaKey;
	
	private static String myPrivatePem;
	
	private static String myPublicPem;

	@BeforeClass
	public static void onlyOnce() throws Exception{
		// Create RSA keys
		myRsaKey = getRsaKey(KID, KEY_ALG);
		
		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		JsonElement json = new JsonParser().parse(myRsaKey.toJSONString());
		System.out.println(String.format("\nPrivate JWK:\n %s", gson.toJson(json)));

		RSAKey myPublicRsaKey = myRsaKey.toPublicJWK();
		gson = new GsonBuilder().setPrettyPrinting().create();
		json = new JsonParser().parse(myPublicRsaKey.toJSONString());
		System.out.println(String.format("\nPublic JWK:\n %s", gson.toJson(json)));
				
		myPrivatePem = outPemFile(myRsaKey.toPrivateKey(), "RSA PRIVATE KEY");		
		System.out.println(myPrivatePem);
		
		myPublicPem = outPemFile(myRsaKey.toPublicKey(), "RSA PUBLIC KEY");		
		System.out.println(myPublicPem);
	}

	
	private static String outPemFile(Key key, String description) throws FileNotFoundException, IOException {
		PemFile pemFile = new PemFile(key, description);
		// pemFile.write(filename);
		// System.out.println(String.format("%s successfully writen in file %s.",
		// description, pemFile.toString()));
				
		return pemFile.toString();
	}

	private static RSAKey getRsaKey(String kid, Algorithm keyAlg) {

		String size = "2048";
		KeyUse keyUse = KeyUse.SIGNATURE;

		Integer keySize = Integer.decode(size);
		RSAKey jwk = RSAKeyMaker.make(keySize, keyUse, keyAlg, kid);

		return jwk;
	}
}