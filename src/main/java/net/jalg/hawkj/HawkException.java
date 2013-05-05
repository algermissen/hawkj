package net.jalg.hawkj;

/** An exception wrapping crypto exception in a single type.
 * 
 * This is a runtime exception because there is typically no sensible way to
 * react on any of the exceptions encapsulated. 
 * 
 * @author Jan Algermissen, http://jalg.net
 *
 */
public class HawkException extends RuntimeException {


	public HawkException(String message, Throwable cause) {
		super(message, cause);
	}

	public HawkException(String message) {
		super(message);
	}

	public HawkException(Throwable cause) {
		super(cause);
	}

}
