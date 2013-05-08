package net.jalg.hawkj;

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;


import net.jalg.hawkj.Algorithm;
import net.jalg.hawkj.AuthorizationHeader;
import net.jalg.hawkj.HawkContext;
import net.jalg.hawkj.HawkException;

import org.junit.Test;

public class WwwAuthenticateHeaderGenerationTest {
	
	// FIXME: implement with implementation of cut.

	@Test
	public void testHeaderGeneration() throws HawkException {
		HawkWwwAuthenticateContext j = HawkWwwAuthenticateContext.tsAndTsm(1, "abcdefghij").credentials("someId", "someKey", Algorithm.SHA_256).build();
		WwwAuthenticateHeader h = j.createWwwAuthenticateHeader();
		assertEquals("Hawk ts=\"1\",tsm=\"abcdefghij\"", h.toString());
	}
	@Test
	public void testHeaderGeneration2() throws HawkException {
		int now = (int) (System.currentTimeMillis() / 1000L);
		HawkWwwAuthenticateContext j = HawkWwwAuthenticateContext.ts().credentials("someId", "someKey", Algorithm.SHA_256).build();
		WwwAuthenticateHeader h = j.createWwwAuthenticateHeader();
		assertTrue(h.getTs() >= now);
	}
	
	@Test
	public void testHeaderGenerationValidHmac() throws HawkException {
		HawkWwwAuthenticateContext j = HawkWwwAuthenticateContext.ts().credentials("someId", "someKey", Algorithm.SHA_256).build();
		WwwAuthenticateHeader h = j.createWwwAuthenticateHeader();
		
		HawkWwwAuthenticateContext k = HawkWwwAuthenticateContext.tsAndTsm(h.getTs(), h.getTsm()).credentials("someId", "someKey", Algorithm.SHA_256).build();
		WwwAuthenticateHeader h2 = k.createWwwAuthenticateHeader();
		assertTrue(j.isValidTimestampMac(h2.getTsm()));
	}
	
	@Test
	public void testHeaderGenerationWrongMacNotValidHmac() throws HawkException {
		int now = (int) (System.currentTimeMillis() / 1000L);
		HawkWwwAuthenticateContext j = HawkWwwAuthenticateContext.ts().credentials("someId", "someKey", Algorithm.SHA_256).build();
		WwwAuthenticateHeader h = j.createWwwAuthenticateHeader();
		assertFalse(j.isValidTimestampMac("ahjghfjwgefj"));
	}
//	
//	@Test
//	public void testHeaderGenerationWithExtData() throws HawkException {
//		HawkContext j = HawkContext.request("GET", "/foo", "example.com", 80).
//		credentials("someId", "someKey", Algorithm.SHA_256).tsAndNonce(1,"abc").ext("some-ext-app-data").build();
//		AuthorizationHeader h = j.createAuthorizationHeader();
//		assertEquals("Hawk id=\"someId\",mac=\"A3A8C89067098581495ACB394F9149487B3B1890365A3510FCB1193A752FFC51\",ts=\"1\",nonce=\"abc\",ext=\"some-ext-app-data\"", h.toString());
//	}
//	
//	@Test
//	public void testHeaderGenerationWithBodyHashing() throws HawkException {
//		HawkContext j = HawkContext.request("GET", "/foo", "example.com", 80).
//		credentials("x", "xxxxx", Algorithm.SHA_256).tsAndNonce(1,"abc").
//				body("Das ist ein toller body".getBytes(StandardCharsets.UTF_8), "text/plain").
//		build();
//		
//		AuthorizationHeader h = j.createAuthorizationHeader();
//		assertEquals("Hawk id=\"x\",mac=\"BC2A5C9BAD29D3D15149E124722C30EA1A8C79BF9B1F0BFAC35E9D332A4BFE06\",hash=\"dMihgvOJ+wzpELyqj4yl72U0mv8ZWI4tvEFcIXk+iD8=\",ts=\"1\",nonce=\"abc\"",
//				h.toString());
//
//	}



}
