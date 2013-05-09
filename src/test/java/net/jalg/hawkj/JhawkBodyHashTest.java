package net.jalg.hawkj;

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;

import net.jalg.hawkj.HawkException;
import net.jalg.hawkj.HawkContext.HawkContextBuilder;

import org.junit.Test;

public class JhawkBodyHashTest {

	@Test
	public void testBodyHashing() throws HawkException {
		byte[] body = "This is a test body of some kind".getBytes(StandardCharsets.UTF_8);
		String hash64 = HawkContextBuilder.generateHash(Algorithm.SHA_256,body,"text/plain");
		System.out.println("HASH" + hash64);
		assertEquals("/CHyeMJ3XrecG754kxnsP1A8X3TY6VjYQD8eCI2wMm4=" , hash64);
	}
	
	@Test
	public void testBodyHashingReturnsSameEveryTime() throws HawkException {
		byte[] body = "This is another a test body of some kind".getBytes(StandardCharsets.UTF_8);
		String hash64_1 = HawkContextBuilder.generateHash(Algorithm.SHA_256,body,"text/plain");
		String hash64_2 = HawkContextBuilder.generateHash(Algorithm.SHA_256,body,"text/plain");
		assertEquals(hash64_1 , hash64_2);
	}
	
	@Test
	public void testMediaTypeParameterStripping() throws HawkException {
		byte[] body = "This is yet another a test body of some kind".getBytes(StandardCharsets.UTF_8);
		String hash64_1 = HawkContextBuilder.generateHash(Algorithm.SHA_256,body,"text/plain; charset=utf-8");
		String hash64_2 = HawkContextBuilder.generateHash(Algorithm.SHA_256,body,"text/plain");
		assertEquals(hash64_1 , hash64_2);
		
		hash64_1 = HawkContextBuilder.generateHash(Algorithm.SHA_256,body,"text/plain ; charset=utf-8");
		hash64_2 = HawkContextBuilder.generateHash(Algorithm.SHA_256,body,"text/plain");
		assertEquals(hash64_1 , hash64_2);
		
		hash64_1 = HawkContextBuilder.generateHash(Algorithm.SHA_256,body," text/plain    ");
		hash64_2 = HawkContextBuilder.generateHash(Algorithm.SHA_256,body,"text/plain ");
		assertEquals(hash64_1 , hash64_2);
	}
	
	@Test(expected = IllegalArgumentException.class)
	public void testNullBodyThrowsException() throws HawkException {
		HawkContextBuilder.generateHash(Algorithm.SHA_256,null,"text/plain");
	}
	@Test(expected = IllegalArgumentException.class)
	public void testEmptyBodyThrowsException() throws HawkException {
		HawkContextBuilder.generateHash(Algorithm.SHA_256,new byte[] {},"text/plain");
	}
	
	@Test(expected = IllegalArgumentException.class)
	public void testNullMediaTypeThrowsException() throws HawkException {
		HawkContextBuilder.generateHash(Algorithm.SHA_256,new byte[] { 'a','b','c'} ,null);
	}
	
	@Test(expected = IllegalArgumentException.class)
	public void testEmptyMediaTypeThrowsException() throws HawkException {
		HawkContextBuilder.generateHash(Algorithm.SHA_256,new byte[] { 'a','b','c'} ,"");
	}
	
	

}
