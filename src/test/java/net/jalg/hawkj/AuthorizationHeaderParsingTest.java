package net.jalg.hawkj;

import static org.junit.Assert.*;


import net.jalg.hawkj.Algorithm;
import net.jalg.hawkj.AuthHeaderParsingException;
import net.jalg.hawkj.AuthorizationHeader;
import net.jalg.hawkj.HawkContext;
import net.jalg.hawkj.HawkContext.HawkContextBuilder;
import net.jalg.hawkj.HawkContext.HawkContextBuilder_C;
import net.jalg.hawkj.HawkContext.HawkContextBuilder_D;
import net.jalg.hawkj.HawkException;

import org.junit.Before;
import org.junit.Test;

public class AuthorizationHeaderParsingTest {

	HawkContextBuilder_C b;
	HawkContext c;


	@Before
	public void init() {
		b = HawkContext.request("GET", "/foo", "example.com", 80).credentials("someId", "someKey", Algorithm.SHA_256);
	}

	@Test(expected = AuthHeaderParsingException.class)
	public void testParsingEmptyStringFails() throws HawkException, AuthHeaderParsingException {
		AuthorizationHeader h;
		h = AuthorizationHeader.authorization("");
	}

	@Test(expected = AuthHeaderParsingException.class)
	public void testParsingBadSchemeFails() throws HawkException, AuthHeaderParsingException {
		String hv = "Hawki id=\"someId\",mac=\"2D320BF8A5948601F9FA3FBA4800C8F7A1D203A317945330854D65228864468D\",ts=\"1\",nonce=\"abc\"";
		AuthorizationHeader.authorization(hv);
	}

	@Test(expected = AuthHeaderParsingException.class)
	public void testParsingBadSyntaxFails1() throws HawkException, AuthHeaderParsingException {
		String hv = "Hawk id=\"someId\",mac\"2D320BF8A5948601F9FA3FBA4800C8F7A1D203A317945330854D65228864468D\",ts=\"1\",nonce=\"abc\"";
		AuthorizationHeader.authorization(hv);
	}
	@Test(expected = AuthHeaderParsingException.class)
	public void testParsingBadSyntaxFails2() throws HawkException, AuthHeaderParsingException {
		String hv = "Hawk id=\"someId\", sometoken68, mac=\"2D320BF8A5948601F9FA3FBA4800C8F7A1D203A317945330854D65228864468D\",ts=\"1\",nonce=\"abc\"";
		AuthorizationHeader.authorization(hv);
	}

	@Test
	public void testx() throws HawkException, AuthHeaderParsingException {
		String hv = "Hawk id=\"someId\",mac=\"2D320BF8A5948601F9FA3FBA4800C8F7A1D203A317945330854D65228864468D\",ts=\"1\",nonce=\"abc\"";
		AuthorizationHeader h;
		h = AuthorizationHeader.authorization(hv);
		assertEquals("someId" , h.getId());
		assertEquals("2D320BF8A5948601F9FA3FBA4800C8F7A1D203A317945330854D65228864468D" , h.getMac());
	}

    @Test
    public void parsingAppSucceeds() throws HawkException, AuthHeaderParsingException {
        String hv = "Hawk id=\"someId\",mac=\"2D320BF8A5948601F9FA3FBA4800C8F7A1D203A317945330854D65228864468D\",ts=\"1\",nonce=\"abc\", app=\"myApp\", dlg=\"peter\"";
        AuthorizationHeader h;
        h = AuthorizationHeader.authorization(hv);
        assertEquals("someId" , h.getId());
        assertEquals("myApp" , h.getApp());
        assertEquals("peter" , h.getDlg());
        assertEquals("2D320BF8A5948601F9FA3FBA4800C8F7A1D203A317945330854D65228864468D" , h.getMac());
    }

    @Test
    public void parsingAndValidationSucceeds() throws HawkException, AuthHeaderParsingException {
        String hv = "Hawk id=\"someId\",mac=\"y+ktx5w5gxwRi4IzwptaDl79q0GG+fD4THhtaKTdZw4=\",ts=\"1\",nonce=\"abc\",app=\"myApp\"";


        AuthorizationHeader h;
        h = AuthorizationHeader.authorization(hv);
        HawkContext j = HawkContext.request("GET", "/foo", "example.com", 80).
                credentials(h.getId(), "someKey", Algorithm.SHA_256).tsAndNonce(h.getTs(),h.getNonce()).app(h.getApp()).build();

        assertEquals("someId" , h.getId());
        assertEquals("myApp" , h.getApp());
        assertEquals("y+ktx5w5gxwRi4IzwptaDl79q0GG+fD4THhtaKTdZw4=" , h.getMac());

        assertTrue(j.isValidMac(h.getMac()));

    }

//    @Test
//    public void testHeaderGenerationWithApp() throws HawkException {
//        HawkContext j = HawkContext.request("GET", "/foo", "example.com", 80).
//                credentials("someId", "someKey", Algorithm.SHA_256).tsAndNonce(1,"abc").app("myApp").build();
//        AuthorizationHeader h = j.createAuthorizationHeader();
//        assertEquals("Hawk id=\"someId\",mac=\"y+ktx5w5gxwRi4IzwptaDl79q0GG+fD4THhtaKTdZw4=\",ts=\"1\",nonce=\"abc\",app=\"myApp\"", h.toString());
//    }






//	@Test
//	public void testHeaderGeneration1() throws HawkException, AuthHeaderParsingException {
//
//		AuthorizationHeader h;
//		h = AuthorizationHeader.authorization("");
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
//		AuthorizationHeader h = j.createAuthorizationHeader();
//		System.out.println("H:" + h.toString());
//	}



}
