package net.jalg.hawkj;

/** Builder implementation for Authorization headers.
 * 
 * @author Jan Algermissen, http://jalg.net
 *
 */
public class AuthorizationHeader {

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
		// FIXME: needs major overhaul
		// beware " escaping
		StringBuilder sb = new StringBuilder(HawkContext.SCHEME).append(" ");
		boolean first = true;
		if (id != null) {
			if (!first) {
				sb.append(",");
			}
			sb.append("id=\"").append(id).append("\"");
			first = false;
		}
		if (mac != null) {
			if (!first) {
				sb.append(",");
			}
			sb.append("mac=\"").append(mac).append("\"");
			first = false;
		}
		if (hash != null) {
			if (!first) {
				sb.append(",");
			}
			sb.append("hash=\"").append(hash).append("\"");
			first = false;
		}
		if (ts != 0) {
			if (!first) {
				sb.append(",");
			}
			sb.append("ts=\"").append(ts).append("\"");
			first = false;
		}
		if (nonce != null) {
			if (!first) {
				sb.append(",");
			}
			sb.append("nonce=\"").append(nonce).append("\"");
			first = false;
		}
		if (ext != null) {
			if (!first) {
				sb.append(",");
			}
			String escaped = ext.replace("\"", "\\\"");
			sb.append("ext=\"").append(escaped).append("\"");
			first = false;
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
				throw new AuthHeaderParsingException("Wrong scheme name " + scheme);
			}
		}
		

		@Override
		public void param(String key, String value)
				throws AuthHeaderParsingException {
			if(value == null) {
				throw new AuthHeaderParsingException("value is null for key: " + key);
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
				} catch(NumberFormatException e) {
					throw new AuthHeaderParsingException(value + " is not an integer value",e);
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
			throw new AuthHeaderParsingException("Token field not supported by Hawk authentication scheme");
		}

	}

}
