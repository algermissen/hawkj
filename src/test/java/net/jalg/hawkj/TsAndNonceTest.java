package net.jalg.jhawk;

import static org.junit.Assert.*;


import net.jalg.hawkj.Algorithm;
import net.jalg.hawkj.AuthorizationHeader;
import net.jalg.hawkj.HawkContext;
import net.jalg.hawkj.HawkContext.HawkContextBuilder;
import net.jalg.hawkj.HawkContext.HawkContextBuilder_B;
import net.jalg.hawkj.HawkContext.HawkContextBuilder_C;
import net.jalg.hawkj.HawkException;

import org.junit.Before;
import org.junit.Test;

public class TsAndNonceTest {

	HawkContextBuilder_B b;
	HawkContext c;
	
	
	@Before
	public void init() {
		b = HawkContext.request("GET", "/foo", "example.com", 80).credentials("someId", "someKey", Algorithm.SHA_256);
	}
	
	@Test
	public void testTesAndNonceShouldBeSetByBuild() throws HawkException {
		c = b.build();
		int now =  (int) (System.currentTimeMillis() / 1000);
		assertTrue(now >= c.getTs());
		assertTrue(c.getNonce() != null);
	}
		
	@Test
	public void testTsAndNonceExplicitlySet() throws HawkException {
		c = b.tsAndNonce(1, "abc").build();
		assertEquals(1,c.getTs());
		assertEquals("abc",c.getNonce());
	}
	
	
	@Test( expected = IllegalArgumentException.class)
	public void test0TsFails() throws HawkException {
		c = b.tsAndNonce(0, "abc").build();
	}
	
	@Test( expected = IllegalArgumentException.class)
	public void testNullNonceFails() throws HawkException {
		c = b.tsAndNonce(1, null).build();
	}
}
