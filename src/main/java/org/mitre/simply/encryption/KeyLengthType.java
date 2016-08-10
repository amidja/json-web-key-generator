package org.mitre.simply.encryption;

public enum KeyLengthType {
	
	SHORTER(56), SHORT(128), LONG(192), LONGER(256), STRONG(512);
	
	private int length;
	
	private KeyLengthType(int length){
		this.length = length;		
	}
	
	public int getLength(){ return length;}	
}
