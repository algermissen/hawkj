package net.jalg.hawkj;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class WwwAuthenticateHeaderParsingTest {
	
	// FIXME: implement with implementation of cut.

//	HawkContextBuilder_B b;
//	HawkContext c;
//	
//	
//	@Before
//	public void init() {
//		b = HawkContext.request("GET", "/foo", "example.com", 80).credentials("someId", "someKey", Algorithm.SHA_256);
//	}
//	
	
	@Test // no exception expected
	public void testParsingSchemaOnly() throws HawkException, AuthHeaderParsingException {
		WwwAuthenticateHeader.wwwAuthenticate("Hawk");
	}	
	
	
	@Test(expected = AuthHeaderParsingException.class)
	public void testParsingEmptyStringFails() throws HawkException, AuthHeaderParsingException {
		WwwAuthenticateHeader.wwwAuthenticate("");
	}
	
	@Test(expected = AuthHeaderParsingException.class)
	public void testParsingSchemeAndToken68Fails() throws HawkException, AuthHeaderParsingException {
		WwwAuthenticateHeader.wwwAuthenticate("Hawk foo");
	}
	
	@Test(expected = AuthHeaderParsingException.class)
	public void testParsingBadSchemeFails() throws HawkException, AuthHeaderParsingException {
		String hv = "Hawki ts=\"1\",tsm=\"abcdefghijk\"";
		WwwAuthenticateHeader.wwwAuthenticate(hv);
	}
	
	@Test(expected = AuthHeaderParsingException.class)
	public void testParsingBadSyntaxFails() throws HawkException, AuthHeaderParsingException {
		String hv = "Hawk ts=\"1\",tsm\"abcdefghijk\"";
		WwwAuthenticateHeader.wwwAuthenticate(hv);
	}
	
	@Test
	public void testParse() throws HawkException, AuthHeaderParsingException {
		String hv = "Hawk ts=\"1\",tsm=\"abcdefghijk\"";
		WwwAuthenticateHeader h = WwwAuthenticateHeader.wwwAuthenticate(hv);
		assertEquals(1 , h.getTs());
		assertEquals("abcdefghijk",h.getTsm());
	}
	
	
	
	@Test
	public void testParsingSchemaOnlyRetrieveScheme() throws HawkException, AuthHeaderParsingException {
		WwwAuthenticateHeader h;
		h = WwwAuthenticateHeader.wwwAuthenticate("Hawk");
		assertEquals("Hawk",h.toString());
	}
	
	@Test
	public void testParseAndToString() throws HawkException, AuthHeaderParsingException {
		String hv = "Hawk ts=\"1\",tsm=\"abcdefghijk\"";
		WwwAuthenticateHeader h = WwwAuthenticateHeader.wwwAuthenticate(hv);
		assertEquals("Hawk ts=\"1\",tsm=\"abcdefghijk\"" , h.toString());
		assertEquals("abcdefghijk",h.getTsm());
	}
	
	@Test
	public void testErrorParseAndToString() throws HawkException, AuthHeaderParsingException {
		String hv = "Hawk error=\"expired\"";
		WwwAuthenticateHeader h = WwwAuthenticateHeader.wwwAuthenticate(hv);
		assertEquals("Hawk error=\"expired\"" , h.toString());
	}
	@Test(expected = AuthHeaderParsingException.class)
	public void testErrorParseUnknownHawkErrorFails() throws HawkException, AuthHeaderParsingException {
		String hv = "Hawk error=\"damaged\"";
		WwwAuthenticateHeader.wwwAuthenticate(hv);
	}
	
	
//	@Test
//	public void testHeaderGeneration1() throws HawkException, AuthHeaderParsingException {
//		
//		WwwAuthenticateHeader h;
//		h = WwwAuthenticateHeader.wwwAuthenticate("");
//		
//		System.out.println("Header: " + h.toString());
//			
//	}
//		
//	@Test
//	public void testHeaderGeneration2() throws HawkException {
//		c = b.tsAndNonce(1, "abc").build();
//		assertEquals(1,c.getTs());
//		assertEquals("abc",c.getNonce());
//	}
//	
//	
//	@Test( expected = IllegalArgumentException.class)
//	public void testHeaderGeneration4() throws HawkException {
//		c = b.tsAndNonce(0, "abc").build();
//	}
//	
//	@Test( expected = IllegalArgumentException.class)
//	public void testHeaderGeneration5() throws HawkException {
//		c = b.tsAndNonce(1, null).build();
//	}
	
	
//	@Test
//	public void test3() throws HawkException {
//		HawkContext j = HawkContext.request("GET", "/foo", "example.com", 80).
//		credentials("x", "xxxxx", Algorithm.SHA_256).tsAndNonce(1,"abc").
//				body("Das ist ein toller body".getBytes(), "text/plain").
//		build();
//		
//		WwwAuthenticateHeader h = j.createWwwAuthenticateHeader();
//		System.out.println("H:" + h.toString());
//	}
	
	

}
