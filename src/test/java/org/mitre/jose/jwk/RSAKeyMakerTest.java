package org.mitre.jose.jwk;

import org.junit.Test;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;

public class RSAKeyMakerTest {

	@Test
	public void testMake() {
		String size = "2048";
		KeyUse keyUse = KeyUse.SIGNATURE;
		Algorithm keyAlg = JWSAlgorithm.RS512;
		String kid = "MyKeyID"; //randomly generate 
		
		Integer keySize = Integer.decode(size);
		JWK jwk = RSAKeyMaker.make(keySize, keyUse, keyAlg, kid);
				
		//System.out.println(jwk);
		
		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		JsonElement json = new JsonParser().parse(jwk.toJSONString());        	
		System.out.println(gson.toJson(json));
		
	}

}
