package org.mitre.jose.jwk;

import static org.junit.Assert.*;

import org.junit.Test;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.ECKey.Curve;


/*Elliptic Curve key generation */
public class ECKeyMakerTest {

	@Test
	public void testMake() {
		KeyUse keyUse = KeyUse.SIGNATURE;
		Algorithm keyAlg = JWSAlgorithm.HS512;
		Curve keyCurve = Curve.parse(Curve.P_256.getName());
					
		JWK jwk = ECKeyMaker.make(keyCurve, keyUse, keyAlg, null);		
				
		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		
		JsonElement json = new JsonParser().parse(jwk.toJSONString());
		System.out.println("JWK:");
		System.out.println(gson.toJson(json));
				
		// also print public key, if possible
		JWK pub = jwk.toPublicJWK();				
    	System.out.println("Public key:");       
        JWKSet jwkSet = new JWKSet(pub);
        
        json = new JsonParser().parse(jwkSet.toJSONObject(false).toJSONString());        	
        System.out.println(gson.toJson(json));
		
	}
}