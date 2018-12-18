package org.me.java.security;

 import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.StringWriter;
import java.security.Key;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Simple utility class that can be used to print or 
 * store RSA Key in the PEM format. 
 *   
 * @author qja266
 *
 */
public class PemFile {
	
	private final Logger LOGGER = LoggerFactory.getLogger(PemFile.class);
	
	private PemObject pemObject;
	
	public PemFile (Key key, String description) {
		this.pemObject = new PemObject(description, key.getEncoded());				
	}
	
	public void write(String filename) throws FileNotFoundException, IOException {
		PemWriter pemWriter = new PemWriter(new OutputStreamWriter(new FileOutputStream(filename)));
		try {
			pemWriter.writeObject(this.pemObject);
		} finally {
			pemWriter.close();
		}
	}
	
	@Override
	public String toString() {
		if (this.pemObject == null) return null;
		
		final StringWriter stringWriter = new StringWriter();		
		PemWriter pemWriter = new PemWriter(stringWriter);
		
		try {
			try {
				pemWriter.writeObject(this.pemObject);
				pemWriter.flush();								
			} finally {
				pemWriter.close();
			}			
		}catch (IOException ex) {
			LOGGER.error("Cannot perform input ", ex);
		}

		return stringWriter.toString();			
	}	
}