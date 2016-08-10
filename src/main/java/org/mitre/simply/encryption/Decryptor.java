package org.mitre.simply.encryption;

import java.security.GeneralSecurityException;

public interface Decryptor {

    public String decrypt(final String strToDecrypt) throws GeneralSecurityException;
    
}
