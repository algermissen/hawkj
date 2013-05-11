package net.jalg.hawkj;

/** Class representing authentication and authorization errors.
 * 
 * This is an extension to Hawk, tailored towards an authorization protocol built on top of Hawk.
 * This is currently <b>not</b> <a href="https://github.com/hueniverse/oz">Oz</a> however, it is related to the ideas of Oz.
 * 
 * FIXME docs
 * 
 * @author Jan Algermissen, http://jalg.net
 *
 */
public enum HawkError {

	EXPIRED("expired", "Credentials expired");

	private final String code;

	private final String text;

	private HawkError(final String code, final String text) {
		this.code = code;
		this.text = text;
	}

	public final String getCode() {
		return this.code;
	}

	public final String getText() {
		return this.text;
	}
	
	public static HawkError fromString(String code) {
		HawkError error = null; // Default
		for (HawkError e : HawkError.values()) {
			if (e.getCode().equals(code)) {
				error = e;
				break;
			}
		}
		return error;
	}

}