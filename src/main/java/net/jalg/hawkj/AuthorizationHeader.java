package net.jalg.hawkj;

/**
 * Builder implementation for Authorization headers.
 * 
 * @author Jan Algermissen, http://jalg.net
 * 
 */
public class AuthorizationHeader {

	private static final char BLANK = ' ';
	private static final char COMMA = ',';
	private static final String ESCDQUOTE = "\"";

	private String id;
	private String mac;
	private String hash;
	private String nonce;
	private int ts;
	private String ext;

	private AuthorizationHeader() {
	}

	public String getId() {
		return id;
	}

	public String getMac() {
		return mac;
	}

	public String getHash() {
		return hash;
	}

	public int getTs() {
		return ts;
	}

	public String getNonce() {
		return nonce;
	}

	public String getExt() {
		return ext;
	}

	public String toString() {
		// beware " escaping
		StringBuilder sb = new StringBuilder(HawkContext.SCHEME);
		char delim = BLANK;
		if (id != null) {
			sb.append(delim).append("id=\"").append(id).append(ESCDQUOTE);
			delim = COMMA;
		}
		if (mac != null) {
			sb.append(delim).append("mac=\"").append(mac).append(ESCDQUOTE);
			delim = COMMA;
		}
		if (hash != null) {
			sb.append(delim).append("hash=\"").append(hash).append(ESCDQUOTE);
			delim = COMMA;
		}
		if (ts != 0) {
			sb.append(delim).append("ts=\"").append(ts).append(ESCDQUOTE);
			delim = COMMA;
		}
		if (nonce != null) {
			sb.append(delim).append("nonce=\"").append(nonce).append(ESCDQUOTE);
			delim = COMMA;
		}
		if (ext != null) {
			String escaped = ext.replace(ESCDQUOTE, "\\\"");
			sb.append(delim).append("ext=\"").append(escaped).append(ESCDQUOTE);
			delim = COMMA;
		}
		return sb.toString();
	}

	public static AuthorizationBuilder authorization() {
		return new AuthorizationBuilder();
	}

	public static AuthorizationHeader authorization(String value)
			throws AuthHeaderParsingException {
		AuthorizationBuilder b = new AuthorizationBuilder();
		AuthDirectiveParser p = new AuthDirectiveParser(value, b);
		p.parse();
		return b.build();
	}

	public static class AuthorizationBuilder implements AuthDirectiveBuilder {
		private String id;
		private String mac;
		private String hash;
		private String nonce;
		private int ts;
		private String ext;

		private AuthorizationBuilder() {

		}

		public AuthorizationHeader build() {
			AuthorizationHeader instance = new AuthorizationHeader();
			instance.id = id;
			instance.hash = hash;
			instance.mac = mac;
			instance.ts = ts;
			instance.nonce = nonce;
			instance.ext = ext;

			return instance;
		}

		public AuthorizationBuilder id(String id) {
			this.id = id;
			return this;
		}

		public AuthorizationBuilder hash(String hash) {
			this.hash = hash;
			return this;
		}

		public AuthorizationBuilder mac(String mac) {
			this.mac = mac;
			return this;
		}

		public AuthorizationBuilder ts(int ts) {
			this.ts = ts;
			return this;
		}

		public AuthorizationBuilder nonce(String nonce) {
			this.nonce = nonce;
			return this;
		}

		public AuthorizationBuilder ext(String ext) {
			this.ext = ext;
			return this;
		}

		@Override
		public void scheme(String scheme) throws AuthHeaderParsingException {
			if (!HawkContext.SCHEME.equalsIgnoreCase(scheme)) {
				throw new AuthHeaderParsingException("Wrong scheme name "
						+ scheme);
			}
		}

		@Override
		public void param(String key, String value)
				throws AuthHeaderParsingException {
			if (value == null) {
				throw new AuthHeaderParsingException("value is null for key: "
						+ key);
			}
			// check null
			key = key.toLowerCase();
			if (key.equals("id")) {
				id(value);
			} else if (key.equals("mac")) {
				mac(value);
			} else if (key.equals("hash")) {
				hash(value);
			} else if (key.equals("ts")) {
				try {
					ts(Integer.parseInt(value));
				} catch (NumberFormatException e) {
					throw new AuthHeaderParsingException(value
							+ " is not an integer value", e);
				}
			} else if (key.equals("nonce")) {
				nonce(value);
			} else if (key.equals("ext")) {
				ext(value);
			} else {
				// FIXME: must-ignore key? Must choke?
			}

		}

		@Override
		public void token(String token) throws AuthHeaderParsingException {
			throw new AuthHeaderParsingException(
					"Token field not supported by Hawk authentication scheme");
		}

	}

}
