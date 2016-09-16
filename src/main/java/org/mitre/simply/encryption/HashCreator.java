package org.mitre.simply.encryption;

public interface HashCreator {
	
	public String hash(final String strToHash);
	
	public void setAlgorithm(String algorithm);
		
}
