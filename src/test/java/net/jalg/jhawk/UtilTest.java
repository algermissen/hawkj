package net.jalg.jhawk;

import static org.junit.Assert.*;


import net.jalg.hawkj.Algorithm;
import net.jalg.hawkj.AuthHeaderParsingException;
import net.jalg.hawkj.AuthorizationHeader;
import net.jalg.hawkj.HawkContext;
import net.jalg.hawkj.HawkContext.HawkContextBuilder;
import net.jalg.hawkj.HawkContext.HawkContextBuilder_B;
import net.jalg.hawkj.HawkContext.HawkContextBuilder_C;
import net.jalg.hawkj.HawkException;
import net.jalg.hawkj.Util;

import org.junit.Before;
import org.junit.Test;

public class UtilTest {

	
	@Test
	public void testGenerateRandomString() throws HawkException, AuthHeaderParsingException {
		String s = Util.generateRandomString(6);
		assertEquals(12,s.length());
	}
	
	@Test
	public void testBytesToHex() {
		byte[] b = { 1 , 2 , 10};
		String s = Util.bytesToHex(b);
		assertEquals("01020A",s);
	}
	
	@Test
	public void testBytesToHexEmpty() {
		byte[] b = { };
		String s = Util.bytesToHex(b);
		assertEquals("",s);
	}
	
	@Test
	public void testBytesToHex00() {
		byte[] b = {0 };
		String s = Util.bytesToHex(b);
		assertEquals("00",s);
	}
	@Test
	public void testBytesToHex0000() {
		byte[] b = {0 , 0};
		String s = Util.bytesToHex(b);
		assertEquals("0000",s);
	}

	
	@Test
	public void testFixedTimeEquals() {
		
		assertTrue(Util.fixedTimeEqual("",""));
		assertTrue(Util.fixedTimeEqual("x","x"));
		assertTrue(Util.fixedTimeEqual("foo","foo"));
		
		assertFalse(Util.fixedTimeEqual("f",""));
		assertFalse(Util.fixedTimeEqual("","f"));
		assertFalse(Util.fixedTimeEqual("foo",""));
		assertFalse(Util.fixedTimeEqual("","foo"));
		assertFalse(Util.fixedTimeEqual("foo","x"));
		assertFalse(Util.fixedTimeEqual("x","foo"));
		assertFalse(Util.fixedTimeEqual("foo","foo1"));
		assertFalse(Util.fixedTimeEqual("foo1","foo"));
		assertFalse(Util.fixedTimeEqual("foo","bar"));
		assertFalse(Util.fixedTimeEqual("foo2","foo1"));
		
	}
}
	