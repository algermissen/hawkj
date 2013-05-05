package net.jalg.hawkj;

/** Exception class for auth-header parsing exceptions.
 * 
 * @author Jan Algermissen, http://jalg.net
 *
 */
public class AuthHeaderParsingException extends Exception {
	
	public AuthHeaderParsingException(String message, Throwable cause) {
		super(message, cause);
	}

	public AuthHeaderParsingException(String message) {
		super(message);
	}

	
}
