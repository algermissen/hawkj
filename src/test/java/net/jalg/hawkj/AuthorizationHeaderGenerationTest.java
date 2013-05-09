package net.jalg.hawkj;

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;


import net.jalg.hawkj.Algorithm;
import net.jalg.hawkj.AuthorizationHeader;
import net.jalg.hawkj.HawkContext;
import net.jalg.hawkj.HawkException;

import org.junit.Test;

public class AuthorizationHeaderGenerationTest {

	@Test
	public void testHeaderGeneration() throws HawkException {
		HawkContext j = HawkContext.request("GET", "/foo", "example.com", 80).
		credentials("someId", "someKey", Algorithm.SHA_256).tsAndNonce(1,"abc").build();
		AuthorizationHeader h = j.createAuthorizationHeader();
		assertEquals("Hawk id=\"someId\",mac=\"LTIL+KWUhgH5+j+6SADI96HSA6MXlFMwhU1lIohkRo0=\",ts=\"1\",nonce=\"abc\"", h.toString());
	}
	
	@Test
	public void testHeaderGenerationWithExtData() throws HawkException {
		HawkContext j = HawkContext.request("GET", "/foo", "example.com", 80).
		credentials("someId", "someKey", Algorithm.SHA_256).tsAndNonce(1,"abc").ext("some-ext-app-data").build();
		AuthorizationHeader h = j.createAuthorizationHeader();
		assertEquals("Hawk id=\"someId\",mac=\"o6jIkGcJhYFJWss5T5FJSHs7GJA2WjUQ/LEZOnUv/FE=\",ts=\"1\",nonce=\"abc\",ext=\"some-ext-app-data\"", h.toString());
	}
	
	@Test
	public void testHeaderGenerationWithBodyHashing() throws HawkException {
		HawkContext j = HawkContext.request("GET", "/foo", "example.com", 80).
		credentials("x", "xxxxx", Algorithm.SHA_256).tsAndNonce(1,"abc").
				body("Das ist ein toller body".getBytes(StandardCharsets.UTF_8), "text/plain").
		build();
		
		AuthorizationHeader h = j.createAuthorizationHeader();
		assertEquals("Hawk id=\"x\",mac=\"vCpcm60p09FRSeEkciww6hqMeb+bHwv6w16dMypL/gY=\",hash=\"dMihgvOJ+wzpELyqj4yl72U0mv8ZWI4tvEFcIXk+iD8=\",ts=\"1\",nonce=\"abc\"",
				h.toString());

	}



}
