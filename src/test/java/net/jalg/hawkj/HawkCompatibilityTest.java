package net.jalg.hawkj;

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;

import net.jalg.hawkj.Algorithm;
import net.jalg.hawkj.AuthorizationHeader;
import net.jalg.hawkj.HawkContext;
import net.jalg.hawkj.HawkException;

import org.junit.Test;

public class HawkCompatibilityTest {

	/**
	 * Adaption of the test 'should generate a normalized string protocol
	 * example' https://github.com/hueniverse/hawk/blob/master/test/readme.js
	 * 
	 * @throws HawkException
	 */
	@Test
	public void testShouldGenerateANormalizedStringProtocolExample() throws HawkException {
		HawkContext j = HawkContext
				.request("GET", "/resource?a=1&b=2", "example.com", 8000)
				.credentials("dh37fgj492je",
						"werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
						Algorithm.SHA_256).tsAndNonce(1353832234, "j4h3g2")
				.ext("some-app-ext-data").build();
		assertEquals(
				j.getBaseString(),
				"hawk.1.header\n1353832234\nj4h3g2\nGET\n/resource?a=1&b=2\nexample.com\n8000\n\nsome-app-ext-data\n");
	}
	

	
	/** Adaption of the test 'should return a valid authorization header (sha1)'
	 * from https://github.com/hueniverse/hawk/blob/master/test/client.js
	 * @throws HawkException
	 */
	//@Test
	public void testShouldReturnAValidAuthorizationHeaderSha1() throws HawkException {
		HawkContext j = HawkContext
				.request("POST", "/somewhere/over/the/rainbow", "example.net",
						80)
				.credentials("123456", "2983d45yun89q", Algorithm.SHA_1)
				.tsAndNonce(1353809207, "Ygvqdz")
				.body("something to write about"
						.getBytes(StandardCharsets.UTF_8),
						"text/plain").ext("Bazinga!").build();
		AuthorizationHeader h = j.createAuthorizationHeader();
		System.out.println(">" + h.toString() + "<");
		assertEquals(
				"Hawk id=\"123456\",mac=\"qbf1ZPG/r/e06F4ht+T77LXi5vw=\",hash=\"bsvY3IfUllw6V5rvk4tStEvpBhE==\",ts=\"1353809207\",nonce=\"Ygvqdz\",ext=\"Bazinga!\"",
				h.toString());
	}
	
	

	/** Adaption of the test 'should return a valid authorization header (sha256)'
	 * from https://github.com/hueniverse/hawk/blob/master/test/client.js
	 * @throws HawkException
	 */
	@Test
	public void testShouldReturnAValidAuthorizationHeaderSha256() throws HawkException {
		HawkContext j = HawkContext
				.request("POST", "/somewhere/over/the/rainbow", "example.net",
						443)
				.credentials("123456", "2983d45yun89q", Algorithm.SHA_256)
				.tsAndNonce(1353809207, "Ygvqdz")
				.body("something to write about"
						.getBytes(StandardCharsets.UTF_8),
						"text/plain").ext("Bazinga!").build();
		AuthorizationHeader h = j.createAuthorizationHeader();
		System.out.println(">" + h.toString() + "<");
		assertEquals(
				"Hawk id=\"123456\",mac=\"q1CwFoSHzPZSkbIvl0oYlD+91rBUEvFk763nMjMndj8=\",hash=\"2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY=\",ts=\"1353809207\",nonce=\"Ygvqdz\",ext=\"Bazinga!\"",
				h.toString());
	}
	
	
	/** Adaption of the test 'should return a valid authorization header (no ext)'
	 * from https://github.com/hueniverse/hawk/blob/master/test/client.js
	 * @throws HawkException
	 */
	@Test
	public void testShouldReturnAValidAuthorizationHeaderNoExt() throws HawkException {
		HawkContext j = HawkContext
				.request("POST", "/somewhere/over/the/rainbow", "example.net",
						443)
				.credentials("123456", "2983d45yun89q", Algorithm.SHA_256)
				.tsAndNonce(1353809207, "Ygvqdz")
				.body("something to write about"
						.getBytes(StandardCharsets.UTF_8),
						"text/plain").build();
		AuthorizationHeader h = j.createAuthorizationHeader();
		System.out.println(">" + h.toString() + "<");
		assertEquals(
				"Hawk id=\"123456\",mac=\"HTgtd0jPI6E4izx8e4OHdO36q00xFCU0FolNq3RiCYs=\",hash=\"2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY=\",ts=\"1353809207\",nonce=\"Ygvqdz\"",
				h.toString());
	}
	
}
