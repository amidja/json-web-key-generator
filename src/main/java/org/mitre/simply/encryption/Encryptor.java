package org.mitre.simply.encryption;

import java.security.GeneralSecurityException;

public interface Encryptor extends Decryptor{

	public String encrypt(final String strToEncrypt) throws GeneralSecurityException;
	
}