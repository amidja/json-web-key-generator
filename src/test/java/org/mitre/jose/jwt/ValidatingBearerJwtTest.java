package org.mitre.jose.jwt;

import java.net.URL;

import org.junit.Ignore;
import org.junit.Test;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

public class ValidatingBearerJwtTest {
	
	// The access token to validate, typically submitted with a HTTP header like
	// Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6InMxIn0.eyJzY3A...
	static final String accessToken =
	    "eyJhbGciOiJSUzI1NiIsImtpZCI6InMxIn0.eyJzY3AiOlsib3BlbmlkIiwiZW1haWwiLCJwcm9maWxl" +
	    "Il0sImV4cCI6MTQ2MDM0NTczNiwic3ViIjoiYWxpY2UiLCJpc3MiOiJodHRwczpcL1wvZGVtby5jMmlk" +
	    "LmNvbVwvYzJpZCIsInVpcCI6eyJncm91cHMiOlsiYWRtaW4iLCJhdWRpdCJdfSwiY2xtIjpbIiE1djhI" +
	    "Il0sImNpZCI6IjAwMDEyMyJ9.Xeg3cMrePht8R0731mfndUDoX48NWhfCuEjcEERcZ3krfnOacNJzyJd" +
	    "7zOWdNrlvEpJMjmmgkbhZOMJlVMv4fQnGB2d3eevmtjuT7hMnJVQc_4h80ODHPMlW27T0Iukpe7Y-A-R" +
	    "rROP5yinry7BFBL2nVWrNtB9IS11H9C8X5fQ";


	@Ignore @Test
	public void testValidatingBearerJwt() throws Exception{
		
		// Set up a JWT processor to parse the tokens and then check their signature
		// and validity time window (bounded by the "iat", "nbf" and "exp" claims)
		ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();

		// The public RSA keys to validate the signatures will be sourced from the
		// OAuth 2.0 server's JWK set, published at a well-known URL. The RemoteJWKSet
		// object caches the retrieved keys to speed up subsequent look-ups and can
		// also gracefully handle key-rollover
		JWKSource keySource = new RemoteJWKSet(new URL("https://demo.c2id.com/c2id/jwks.json"));

		// The expected JWS algorithm of the access tokens (agreed out-of-band)
		JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;

		// Configure the JWT processor with a key selector to feed matching public
		// RSA keys sourced from the JWK set URL
		JWSKeySelector keySelector = new JWSVerificationKeySelector(expectedJWSAlg, keySource);
		jwtProcessor.setJWSKeySelector(keySelector);

		// Process the token
		SecurityContext ctx = null; // optional context parameter, not required here
		JWTClaimsSet claimsSet = jwtProcessor.process(accessToken, ctx);

		// Print out the token claims set
		System.out.println(claimsSet.toJSONObject());
		
	}
}
