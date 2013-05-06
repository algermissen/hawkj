package net.jalg.hawkj;

import net.jalg.hawkj.Algorithm;
import net.jalg.hawkj.HawkContext;
import net.jalg.hawkj.HawkException;

import org.junit.Test;

public class FailingExtSpecialCharsTest {

	@Test( expected = RuntimeException.class)
	public void testHeaderGenerationWithDoubleQuoteInExtDataFails() throws HawkException {
		HawkContext.request("GET", "/foo", "example.com", 80).
		credentials("someId", "someKey", Algorithm.SHA_256).tsAndNonce(1,"abc").ext("some-ext-\"app-data").build();
	}
	
	@Test( expected = RuntimeException.class)
	public void testHeaderGenerationWithLFInExtDataFails() throws HawkException {
		HawkContext.request("GET", "/foo", "example.com", 80).
		credentials("someId", "someKey", Algorithm.SHA_256).tsAndNonce(1,"abc").ext("some-ext-\napp-data").build();
	}
	
	@Test( expected = RuntimeException.class)
	public void testHeaderGenerationWithBackslashInExtDataFails() throws HawkException {
		HawkContext.request("GET", "/foo", "example.com", 80).
		credentials("someId", "someKey", Algorithm.SHA_256).tsAndNonce(1,"abc").ext("some-ext-\\app-data").build();
	}

}
