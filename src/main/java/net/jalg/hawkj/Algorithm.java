package net.jalg.hawkj;

/**
 * A representation of hashing algorithms.
 * 
 * Several algorithms are provided by this enum. For a list of possible names
 * refer to <href=
 * "http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Mac"
 * >Mac Algorithm Names</a> and <href=
 * "http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#MessageDigest"
 * >MessageDigest Algorithm Names</a>
 * 
 * and add constants as needed.
 * 
 * @author Jan Algermissen, http://jalg.net
 * 
 */
public enum Algorithm {

	/**
	 * MD5
	 * 
	 */
	MD5("md5", "HmacMD5", "MD5"),

	/**
	 * SHA1
	 * 
	 */
	SHA_1("sha1", "HmacSHA1", "SHA-1"),

	/**
	 * SHA256
	 * 
	 */
	SHA_256("sha256", "HmacSHA256", "SHA-256");

	/** The name to use for identifying this algorithm */
	private final String name;
	/** The name to pass to the Mac.init() method */
	private final String macName;
	/** The name to pass to the MessageDigest.getInstance() method. */
	private final String messageDigestName;

	/**
	 * Create an algorithm.
	 * 
	 * @param name The name to use for identifying this algorithm
	 * @param macName The name to pass to the Mac.init() method
	 * @param digestName The name to pass to the MessageDigest.getInstance() method
	 */
	private Algorithm(final String name, final String macName,
			final String messageDigestName) {
		this.name = name;
		this.macName = macName;
		this.messageDigestName = messageDigestName;
	}

	/**
	 * Get the name of the algorithm.
	 * 
	 * This is the name to identify this algorithm.
	 * 
	 * @return The name
	 */
	public String getName() {
		return name;
	}

	/** Get the Mac name of the algorithm
	 * 
	 * This is the name to pass to the Mac.init() method
	 * 
	 * @return
	 */
	public String getMacName() {
		return macName;
	}

	/**
	 * Get the MessageDigest name of the algorithm.
	 * 
	 * This is the string to pass to MessageDigest.getInstance().
	 * 
	 * @return The name
	 */
	public String getMessageDigestName() {
		return messageDigestName;
	}

	/**
	 * Find the constant corresponding to an algorithm name.
	 * 
	 * Given a name, this method searches the list of available algorithms and
	 * returns the matching one. If none match, null is returned. For a list of
	 * names please refer to <href=
	 * "http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Mac"
	 * >Mac Algorithm Names</a>
	 * <p>
	 * Mathching is case-sensitive.
	 * 
	 * 
	 * 
	 * @param name
	 *            Java crypto extension name of the algorithm
	 * @return The algorithm or null if none matches.
	 */
	public static Algorithm fromString(String name) {
		Algorithm algorithm = null; // Default
		for (Algorithm a : Algorithm.values()) {
			if (a.getName().equals(name)) {
				algorithm = a;
				break;
			}
		}
		return algorithm;
	}
	
	/* (non-Javadoc)
	 * @see java.lang.Enum#toString()
	 */
	public String toString() {
		return "Algorithm: " + getName();
		
	}

}
