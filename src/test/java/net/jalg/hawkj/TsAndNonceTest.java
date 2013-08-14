package net.jalg.hawkj;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import net.jalg.hawkj.HawkContext.HawkContextBuilder_C;

import org.junit.Before;
import org.junit.Test;

public class TsAndNonceTest {

	HawkContextBuilder_C b;
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
