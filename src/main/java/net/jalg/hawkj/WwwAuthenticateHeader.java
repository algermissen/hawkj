package net.jalg.hawkj;


/** Builder implementation for WWW-Authenticate headers.
 * 
 * 
 * @author Jan Algermissen, http://jalg.net
 *
 */
public class WwwAuthenticateHeader {

	private String realm;
	private HawkError error;
//	private boolean isReadonly;
//	private boolean requireOwner;

	public String toString() {
		// beware " escaping
		StringBuilder sb = new StringBuilder(HawkContext.SCHEME).append(" ");
		boolean first = true;
		if (realm != null) {
			if (!first) {
				sb.append(",");
			}
			sb.append("realm=\"").append(realm).append("\"");
			first = false;
		}
		if (error != null) {
			if (!first) {
				sb.append(",");
			}
			sb.append("error=\"").append(error).append("\"");
			first = false;
		}
		// FIXME: others
		return sb.toString();
	}

	private WwwAuthenticateHeader() {
//		isReadonly = true;
//		requireOwner = true;
	}

	public static WwwAuthenticateBuilder wwwAuthenticate() {
		return new WwwAuthenticateBuilder();
	}

	public static WwwAuthenticateHeader wwwAuthenticate(String value)
			throws AuthHeaderParsingException {
		WwwAuthenticateBuilder b = new WwwAuthenticateBuilder();
		AuthDirectiveParser p = new AuthDirectiveParser(value, b);
		p.parse();
		return b.build();
	}

	public static class WwwAuthenticateBuilder implements AuthDirectiveBuilder {
		private String realm;
		private HawkError error;

		private WwwAuthenticateBuilder() {

		}

		public WwwAuthenticateHeader build() {
			WwwAuthenticateHeader instance = new WwwAuthenticateHeader();
			instance.realm = this.realm;
			instance.error = this.error;
			return instance;
		}

		public WwwAuthenticateBuilder realm(String realm) {
			this.realm = realm;
			return this;
		}

		public WwwAuthenticateBuilder error(HawkError error) {
			this.error = error;
			return this;
		}

		@Override
		public void scheme(String scheme) throws AuthHeaderParsingException {
			if (!"hawk".equals(scheme.toLowerCase())) {
				throw new AuthHeaderParsingException("Wrong auth scheme name " + scheme.toLowerCase());
			}
		}

		@Override
		public void param(String key, String value)
				throws AuthHeaderParsingException {
			// check null
			key = key.toLowerCase();
			if (key.equals("realm")) {
				realm(value);
				if (key.equals("error")) {
					error(error);
				} else {
					// FIXME: must-ignore key.
				}

			}

		}

		@Override
		public void token(String token) throws AuthHeaderParsingException {
			throw new AuthHeaderParsingException("Token field not supported by Hawk authentication scheme");
			
		}
	}

}
