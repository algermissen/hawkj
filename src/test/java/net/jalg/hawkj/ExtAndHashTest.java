package net.jalg.hawkj;

import static org.junit.Assert.*;


import net.jalg.hawkj.Algorithm;
import net.jalg.hawkj.AuthorizationHeader;
import net.jalg.hawkj.HawkContext;
import net.jalg.hawkj.HawkContext.HawkContextBuilder;
import net.jalg.hawkj.HawkContext.HawkContextBuilder_C;
import net.jalg.hawkj.HawkException;

import org.junit.Before;
import org.junit.Test;

public class ExtAndHashTest {

	HawkContextBuilder_C b;
	HawkContext c;
	
	
	@Before
	public void init() {
		b = HawkContext.request("GET", "/foo", "example.com", 80).credentials("someId", "someKey", Algorithm.SHA_256).tsAndNonce(1,"abc");
	}
	
	@Test
	public void testLastExtWins() throws HawkException {
		c = b.ext("xxx").ext("yyy").build();
		assertEquals("yyy",c.getExt());
	}
		
	@Test
	public void testLastHashWins() throws HawkException {
		c = b.hash("abcdef").hash("ghij").build();
		assertEquals("ghij",c.getHash());
	}
	@Test
	public void testNullExtIsIgnored() throws HawkException {
		c = b.ext(null).build();
		assertEquals(null,c.getExt());
	}
	
	@Test
	public void testEmptyExtIsIgnored() throws HawkException {
		c = b.ext("").build();
		assertEquals(null,c.getExt());
	}
	
	@Test
	public void testWhitespaceExtIsNotIgnored() throws HawkException {
		c = b.ext("  ").build();
		assertEquals("  ",c.getExt());
	}
	
	@Test( expected = IllegalStateException.class)
	public void testHashAndBodyFails() throws HawkException {
		c = b.hash("abcdef").body(new byte[] {'a','b','c'} , "text/plain").build();
	}
	
	@Test( expected = IllegalStateException.class)
	public void testBodyAndHashFails() throws HawkException {
		c = b.body(new byte[] {'a','b','c'} , "text/plain").hash("abcdef").build();
	}
	

}
