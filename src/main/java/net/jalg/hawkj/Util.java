package net.jalg.hawkj;

import java.security.SecureRandom;
import java.util.Random;


public class Util {
	
	/**
	 * Convert a byte array to a string using. This method turns a byte array
	 * into a string using two characters per byte and encoding the byte value
	 * as a two character hex value.
	 * <p>
	 * The resulting string will have a length twice as long as the original
	 * byte array.
	 * </p>
	 * <p>
	 * The string will be suitable for use in URLs or HTTP headers etc. without
	 * further escaping.
	 * </p>
	 * 
	 * 
	 * @param bytes
	 *            The byte array to turn into a string.
	 * @return Byes of the array as a string.
	 */
	public static String bytesToHex(byte[] bytes) {
		final char[] hexArray = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
				'9', 'A', 'B', 'C', 'D', 'E', 'F' };
		char[] hexChars = new char[bytes.length * 2];
		int v;
		for (int j = 0; j < bytes.length; j++) {
			v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}
	
	/** Generate a random string with a certain entropy.
	 * 
	 * This creates a random string with the entropy of nbytes and encodes
	 * that string in hex format. That means, the returned string will be
	 * twice as long as the requested entropy.
	 * <p>
	 * The string will be suitable for use in URLs or HTTP headers etc. without
	 * further escaping.
	 * </p>
	 * 
	 * 
	 * @param nbytes Number of bytes for entryopy
	 * 
	 * @return Hex encoded random string of length 2 x nbytes.
	 */
	public static String generateRandomString(int nbytes) {
		byte[] salt = new byte[nbytes];
		Random r = new SecureRandom();
		r.nextBytes(salt);
		return bytesToHex(salt);
	}
	
	/** Fixed time comparison of two strings.
	 * 
	 * Fixed time comparison is necessary in order to prevent attacks analyzing differences in
	 * verification time for corrupted tokens.
	 * 
	 * @param lhs Left hand side operand
	 * @param rhs Right hadn side operand
	 * @return true if the strings are equal, false otherwise.
	 */
	public static boolean fixedTimeEqual(String lhs, String rhs) {
		
		boolean equal = (lhs.length() == rhs.length() ? true : false);
		
		// If not equal, work on a single operand to have same length.
		if(!equal) {
			rhs = lhs;
		}
		int len = lhs.length();
		for(int i=0;i<len;i++) {
			if(lhs.charAt(i) == rhs.charAt(i)) {
				equal = equal && true;
			} else {
				equal = equal && false;
			}
		}
		
		return equal;
	}

}
