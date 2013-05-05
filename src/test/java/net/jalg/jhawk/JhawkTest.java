package net.jalg.jhawk;

import static org.junit.Assert.*;


import net.jalg.hawkj.Algorithm;
import net.jalg.hawkj.AuthorizationHeader;
import net.jalg.hawkj.HawkContext;
import net.jalg.hawkj.HawkException;

import org.junit.Test;

public class JhawkTest {

	@Test
	public void test2() throws HawkException {
		HawkContext j = HawkContext.request("GET", "/foo", "example.com", 80).
		credentials("x", "xxxxx", Algorithm.SHA_256).tsAndNonce(1,"abc").build();
		
		AuthorizationHeader h = j.createAuthorizationHeader();
		System.out.println("H:" + h.toString());
	}

	@Test
	public void test3() throws HawkException {
		HawkContext j = HawkContext.request("GET", "/foo", "example.com", 80).
		credentials("x", "xxxxx", Algorithm.SHA_256).tsAndNonce(1,"abc").
				body("Das ist ein toller body".getBytes(), "text/plain").
		build();
		
		AuthorizationHeader h = j.createAuthorizationHeader();
		System.out.println("H:" + h.toString());
	}

}
