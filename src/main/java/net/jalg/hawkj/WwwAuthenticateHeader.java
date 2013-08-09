package net.jalg.hawkj;

/**
 * Builder implementation for WWW-Authenticate headers.
 * 
 * @author Jan Algermissen, http://jalg.net
 * 
 */
public class WwwAuthenticateHeader {

	private static final char BLANK = ' '; 
	private static final char COMMA = ','; 
	private static final String ESCDQUOTE = "\""; 
	
//	private String realm;
	private HawkError error;
	private int ts;
	private String tsm;

	// private boolean isReadonly;
	// private boolean requireOwner;
	
	private WwwAuthenticateHeader() {
		// isReadonly = true;
		// requireOwner = true;
	}
	
	public int getTs() {
		return ts;
	}
	
	public String getTsm() {
		return tsm;
	}
	
	public boolean hasTs() {
		return ts != 0;
	}

	public String toString() {
		//FIXME  beware " escaping
		StringBuilder sb = new StringBuilder(HawkContext.SCHEME);
		char delim = BLANK;
		// FIXME: integrate realm
//		if (realm != null) {
//			sb.append(delim).append("realm=\"").append(realm).append(ESCDQUOTE);
//			delim = COMMA;
//		}
		if (ts != 0) {
			sb.append(delim).append("ts=\"").append(ts).append(ESCDQUOTE);
			delim = COMMA;
		}
		if (tsm != null) {
			sb.append(delim).append("tsm=\"").append(tsm).append(ESCDQUOTE);
			delim = COMMA;
		}
		if (error != null) {
			sb.append(delim).append("error=\"").append(error.getCode()).append(ESCDQUOTE);
			delim = COMMA;
		}
		// FIXME: extension elements?
		return sb.toString();
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
//		private String realm;
		private HawkError error;
		private int ts;
		private String tsm;

		private WwwAuthenticateBuilder() {

		}

		public WwwAuthenticateHeader build() {
			WwwAuthenticateHeader instance = new WwwAuthenticateHeader();
//			instance.realm = this.realm;
			instance.error = this.error;
			instance.ts = this.ts;
			instance.tsm = this.tsm;
			return instance;
		}

//		public WwwAuthenticateBuilder realm(String realm) {
//			this.realm = realm;
//			return this;
//		}

		public WwwAuthenticateBuilder error(HawkError error) {
			this.error = error;
			return this;
		}
		public WwwAuthenticateBuilder ts(int ts) {
			this.ts = ts;
			return this;
		}
		public WwwAuthenticateBuilder tsm(String tsm) {
			this.tsm = tsm;
			return this;
		}
	

		@Override
		public void scheme(String scheme) throws AuthHeaderParsingException {
			if (!HawkContext.SCHEME.equalsIgnoreCase(scheme)) {
				throw new AuthHeaderParsingException("Wrong auth scheme name "
						+ scheme);
			}
		}

		@Override
		public void param(String key, String value)
				throws AuthHeaderParsingException {
			// check null
			key = key.toLowerCase();
//			if (key.equals("realm")) {
//				realm(value);
			if (key.equals("ts")) {
				try {
					ts(Integer.parseInt(value));
				} catch(NumberFormatException e) {
					throw new AuthHeaderParsingException(value + " is not an integer value",e);
				}
			} else if (key.equals("tsm")) {
				tsm(value);
			} else if (key.equals("error")) {
				HawkError e = HawkError.fromString(value);
				if(e == null) {
					throw new AuthHeaderParsingException(value + "is not a recognized Hawk error");
				}
				error(e); 
			} else {
				// FIXME: must-ignore key. Or parse extension?
			}

		}

		@Override
		public void token(String token) throws AuthHeaderParsingException {
			throw new AuthHeaderParsingException(
					"Token field not supported by Hawk authentication scheme");

		}
	}

}
