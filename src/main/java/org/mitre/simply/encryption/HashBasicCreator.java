package org.mitre.simply.encryption;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component("hashBasicCreator")
public class HashBasicCreator implements HashCreator {

	private static final Logger logger = LoggerFactory.getLogger(HashBasicCreator.class);
	
	private String algorithm;
	
	@Override
	public String hash(String strToHash)  {
		 
	        String generatedHash = null;
	        
	        try {
	            // Create MessageDigest instance for MD5
	            //MessageDigest md = MessageDigest.getInstance("MD5");
	        	MessageDigest md = MessageDigest.getInstance(getAlgorithm());
	            //Add password bytes to digest
	        	
	        	byte[] bytes = null;
	        	byte[] salt = getSalt(); 
	        	if (salt == null){
	        		md.update(strToHash.getBytes());
	        		bytes = md.digest();
	        	}else{
	        		md.update(salt);
	        		bytes = md.digest(strToHash.getBytes());
	        	}
	        	
	            //This bytes[] has bytes in decimal format;
	            //Convert it to hexadecimal format
	            StringBuilder sb = new StringBuilder();
	            for(int i=0; i< bytes.length ;i++){
	                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
	            }
	            //Get complete hashed password in hex format
	            generatedHash = sb.toString();
	        } catch (NoSuchAlgorithmException ea) {
	            ea.printStackTrace();
	        } catch (NoSuchProviderException ep){
	        	ep.printStackTrace();
	        }
	        
	        return generatedHash;
	}

	@Override
	public void setAlgorithm(String algorithm) {
		this.algorithm = algorithm;	
	}

	public String getAlgorithm() {
		return algorithm;
	}
	
	protected static byte[] getSalt() throws NoSuchAlgorithmException, NoSuchProviderException{
		return null;
	}
	
}
