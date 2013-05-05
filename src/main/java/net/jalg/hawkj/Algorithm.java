package net.jalg.hawkj;

/**
 * A representation of hashing algorithms.
 * 
 * Several algorithms are provided by this enum. For a list of possible names
 * refer to <href=
 * "http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Mac"
 * >Mac Algorithm Names</a> and add constants as needed.
 * 
 * @author Jan Algermissen, http://jalg.net
 * 
 */
public enum Algorithm {

	/**
	 * MD5
	 * 
	 */
	MD5("HmacMD5"),

	/**
	 * SHA1
	 * 
	 */
	SHA_1("HmacSHA1"),

	/**
	 * SHA256
	 * 
	 */
	SHA_256("HmacSHA256");

	/** The name to pass to the MessageDigest.getInstance() method. */
	private final String name;

	/** Create an algorithm.
	 * 
	 * @param name
	 */
	private Algorithm(final String name) {
		this.name = name;
	}

	/** Get the name of the algorithm.
	 * 
	 * This is the string to pass to MessageDigest.getInstance().
	 * 
	 * @return The name
	 */
	public String getName() {
		return name;
	}

	/**
	 * Find the constant corresponding to an algorithm name.
	 * 
	 * Given a name, this method searches the list of available algorithms and returns the matching one.
	 * If none match, null is returned. For a list of names please refer to
	 * <href=
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

	@Override
	public String toString() {
		return getName();
	}

}
